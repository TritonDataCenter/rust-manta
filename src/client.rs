use crate::ssh::{SshAgentClient, SshIdentity};
use std::env;
use std::io::ErrorKind;

use futures_util::TryStreamExt;
use reqwest::{Method, RequestBuilder, Response, Url};

use crate::codec::EntryCodec;
use serde::Deserialize;
use time::OffsetDateTime;
use tokio::io::AsyncBufRead;
use tokio_util::codec::FramedRead;
use tokio_util::io::StreamReader;
use tracing::{level_filters::LevelFilter, subscriber, trace};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::{layer::SubscriberExt, Layer, Registry};
use url::ParseError;

/// Errors related to HTTP client
#[derive(Debug, Clone)]
pub enum HttpError {
    ParseError,
    ReqwestError,
    JsonError,
    IOError,
    GenericError,
}

impl From<ParseError> for HttpError {
    fn from(_: ParseError) -> Self {
        HttpError::ParseError
    }
}

impl From<reqwest::Error> for HttpError {
    fn from(_: reqwest::Error) -> Self {
        HttpError::ReqwestError
    }
}

impl From<serde_json::Error> for HttpError {
    fn from(_: serde_json::Error) -> Self {
        HttpError::JsonError
    }
}

impl From<std::io::Error> for HttpError {
    fn from(_: std::io::Error) -> Self {
        HttpError::IOError
    }
}

// Manta client configuration
#[derive(Debug)]
pub struct Config {
    /// Manta Account.
    pub account: String,

    /// Manta User (login name).
    pub user: Option<String>,

    /// Assume a role. Use multiple times or once with a list.
    pub role: Option<Vec<String>>,

    ///  Do not validate SSL certificate.
    pub insecure: bool,

    /// SSH key fingerprint.
    pub key: String,

    /// SSH Auth Socket
    pub ssh_auth_socket: String,

    /// Manta URL.
    pub url: String,

    pub log: Option<LogOptions>,
}

impl Config {
    pub fn new_from_defaults() -> Config {
        Self {
            account: env::var("MANTA_USER").unwrap_or_default(),
            user: None,
            role: None,
            insecure: false,
            key: env::var("MANTA_KEY_ID").unwrap_or_default(),
            ssh_auth_socket: env::var("SSH_AUTH_SOCK").unwrap_or_default(),
            url: env::var("MANTA_URL")
                .unwrap_or(String::from("https://us-central.manta.mnx.io")),
            log: None,
        }
    }
}

#[derive(Debug)]
pub struct LogOptions {
    level: LevelFilter,
    name: String,
}

impl LogOptions {
    pub fn new<N: Into<String>>(level: u8, name: N) -> Self {
        let log_level = match level {
            0 => LevelFilter::OFF,
            1 => LevelFilter::INFO,
            2 => LevelFilter::DEBUG,
            3 | _ => LevelFilter::TRACE,
        };
        Self {
            level: log_level,
            name: name.into(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct MantaObject {
    pub name: String,
    pub etag: Option<String>,
    #[serde(with = "time::serde::iso8601")]
    pub mtime: OffsetDateTime,
    #[serde(default)]
    pub size: u64,
    pub content_type: Option<String>,
    pub content_md5: Option<String>,
    #[serde(default)]
    pub durability: u8,
}

#[derive(Deserialize, Debug)]
pub struct MantaDirectory {
    pub name: String,
    #[serde(with = "time::serde::iso8601")]
    pub mtime: OffsetDateTime,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DirectoryEntry {
    Object(MantaObject),
    Directory(MantaDirectory),
}

/// If the manta paths starts with ~~ it is replaces with the account name
fn normalize_path<P: Into<String>>(account: &str, path_input: P) -> String {
    let path = path_input.into();
    if path.starts_with("~~") {
        return path.replace("~~", account);
    }
    path
}

fn to_tokio_async_read(
    r: impl futures::io::AsyncRead,
) -> impl tokio::io::AsyncRead {
    tokio_util::compat::FuturesAsyncReadCompatExt::compat(r)
}

pub struct Client {
    http_client: reqwest::Client,
    ssh_agent_client: SshAgentClient,
    identity: SshIdentity,
    config: Config,
}

impl Client {
    pub fn new(config: Config) -> Self {
        let http_client = reqwest::Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .expect("Failed to build HTTP Client");

        let mut ssh_agent_client = SshAgentClient::new(&config.ssh_auth_socket);

        let mut identities = ssh_agent_client.list_identities();

        if let Some(log) = &config.log {
            let formatting_layer =
                BunyanFormattingLayer::new(log.name.clone(), std::io::stderr)
                    .with_filter(log.level);
            let subscriber = Registry::default()
                .with(JsonStorageLayer)
                .with(formatting_layer);
            subscriber::set_global_default(subscriber)
                .expect("Failed to initialize logger");
        }

        trace!("found {:?} ssh identities", identities.len());

        let idx = identities
            .iter()
            .position(|ref ident| {
                ident.md5_fp == config.key || ident.sha256_fp == config.key
            })
            .expect("Failed to find key in ssh-agent");

        let identity = identities.remove(idx);

        trace!("Using identity: {}", identity);

        Self {
            http_client,
            ssh_agent_client,
            identity,
            config,
        }
    }

    pub async fn request(
        &mut self,
        method: Method,
        path: &str,
    ) -> Result<RequestBuilder, HttpError> {
        let path_string = normalize_path(&self.config.account, path);
        let url =
            Url::parse(self.config.url.as_str())?.join(path_string.as_str())?;

        let date = crate::ssh::rfc1123();
        let date_header = format!("date: {}", date);
        let data = date_header.as_bytes();
        let signature = self.ssh_agent_client.sign_data(&self.identity, data);

        let key_id =
            format!("/{}/keys/{}", self.config.account, &self.identity.md5_fp);
        let authorization =
            crate::ssh::auth_header(&key_id, "rsa-sha1", &signature);

        Ok(self
            .http_client
            .request(method, url)
            .header("date", date)
            .header("authorization", authorization))
    }

    pub async fn ls(
        &mut self,
        path: &str,
    ) -> Result<FramedRead<impl tokio::io::AsyncRead, EntryCodec>, HttpError>
    {
        // XXX first make a HEAD request to ensure path is a directory

        let stream = self
            .request(Method::GET, path)
            .await?
            .send()
            .await?
            .error_for_status()?
            .bytes_stream()
            .map_err(|e| {
                futures::io::Error::new(futures::io::ErrorKind::Other, e)
            })
            .into_async_read();

        let tokio_async_read = to_tokio_async_read(stream);
        Ok(FramedRead::new(tokio_async_read, EntryCodec::new()))
    }

    pub async fn get(
        &mut self,
        path: &str,
    ) -> Result<impl tokio::io::AsyncRead + AsyncBufRead + Unpin, HttpError>
    {
        let stream = self
            .request(Method::GET, path)
            .await?
            .send()
            .await?
            .error_for_status()?
            .bytes_stream()
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e));
        Ok(StreamReader::new(stream))
    }

    pub async fn rm(&mut self, path: &str) -> Result<Response, HttpError> {
        Ok(self
            .request(Method::DELETE, path)
            .await?
            .send()
            .await?
            .error_for_status()?)
    }
}
