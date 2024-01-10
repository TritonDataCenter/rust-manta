// Copyright 2018 Joyent, Inc.
// Copyright 2024 MNX Cloud, Inc.

use std::fmt;
use std::io::prelude::*;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use md5::Md5;
use sha2::{Digest, Sha256};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

use base64::Engine;
use base64::{
    alphabet::STANDARD as B64_STANDARD,
    engine::general_purpose::NO_PAD as B64_NO_PAD,
    engine::GeneralPurpose as B64Engine,
};

static RFC1123_FORMAT: &[FormatItem] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

static BASE64: B64Engine = B64Engine::new(&B64_STANDARD, B64_NO_PAD);

fn read_string(buf: &[u8], offset: usize, len: usize) -> String {
    let slice = &buf[offset..(offset + len) as usize];
    String::from_utf8(slice.to_vec()).expect("Failed to read string")
}

fn read_u32be(buf: &[u8], offset: usize) -> u32 {
    ((buf[offset] as u32) << 24)
        + ((buf[offset + 1] as u32) << 16)
        + ((buf[offset + 2] as u32) << 8)
        + (buf[offset + 3] as u32)
}

pub(crate) fn rfc1123() -> String {
    OffsetDateTime::now_utc().format(&RFC1123_FORMAT).unwrap()
}

pub(crate) fn auth_header(
    key_id: &str,
    algorithm: &str,
    signature: &str,
) -> String {
    format!(
        "Signature keyId=\"{}\",algorithm=\"{}\",headers=\"date\",signature=\"{}\"",
        key_id, algorithm, signature
    )
}

pub struct SshAgentClient {
    stream: UnixStream,
    #[allow(dead_code)]
    socket_path: String,
}

impl SshAgentClient {
    const SSH_AGENTC_REQUEST_RSA_IDENTITIES: u8 = 11;
    const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
    const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;
    const SSH2_AGENT_SIGN_RESPONSE: u8 = 14;

    pub fn new(socket_path: &str) -> SshAgentClient {
        let stream = UnixStream::connect(&socket_path)
            .expect("failed to connect to socket");

        stream
            .set_read_timeout(Some(Duration::new(1, 0)))
            .expect("failed to set_read_timeout");

        SshAgentClient {
            socket_path: socket_path.to_string(),
            stream,
        }
    }

    pub fn list_identities(&mut self) -> Vec<SshIdentity> {
        let mut identities: Vec<SshIdentity> = Vec::new();

        // write request for identities
        let buf = [0, 0, 0, 1, Self::SSH_AGENTC_REQUEST_RSA_IDENTITIES];
        let rv = self.stream.write(&buf).expect("Failed to write to socket");
        assert_eq!(rv, 5);

        // read the response length first
        let mut buf = vec![0; 4];
        let rv = self
            .stream
            .read(&mut buf)
            .expect("Failed to read from socket");
        assert_eq!(rv, 4);
        let len = read_u32be(&buf, 0);

        // read the rest of the response
        let mut buf = vec![0; len as usize];
        self.stream
            .read_exact(&mut buf)
            .expect("Failed to read from socket");

        let mut idx = 0;

        // first byte should be the correct response type
        let response_type = read_u8(&buf, idx);
        assert_eq!(response_type, Self::SSH_AGENT_IDENTITIES_ANSWER);
        idx += 1;

        // next u32 is the number of keys in the agent
        let num_keys = read_u32be(&buf, idx);
        idx += 4;

        // loop each key found
        for _ in 0..num_keys {
            // Read key len
            let len = read_u32be(&buf, idx) as usize;
            idx += 4;

            // Extract the bytes for the key
            let bytes = &buf[idx..(idx + len)];
            idx += len;

            // Read the comment
            let len = read_u32be(&buf, idx) as usize;
            idx += 4;
            let comment = read_string(&buf, idx, len);
            idx += len;

            // Make a new SshIdentity
            let ident = SshIdentity::new(bytes, &comment);
            identities.push(ident);
        }

        identities
    }

    pub fn sign_data(&mut self, identity: &SshIdentity, data: &[u8]) -> String {
        let mut idx = 0;
        let mut buf =
            vec![0; 4 + 1 + 4 + identity.raw_key.len() + 4 + data.len() + 4];

        let len = buf.len() - 4;
        write_u32be(&mut buf, len as u32, idx);
        idx += 4;

        write_u8(&mut buf, Self::SSH2_AGENTC_SIGN_REQUEST, idx);
        idx += 1;

        write_u32be(&mut buf, identity.raw_key.len() as u32, idx);
        idx += 4;

        write_bytes(&mut buf, &identity.raw_key, idx);
        idx += identity.raw_key.len();

        write_u32be(&mut buf, data.len() as u32, idx);
        idx += 4;

        write_bytes(&mut buf, data, idx);
        idx += data.len();

        write_u32be(&mut buf, 0, idx);
        idx += 4;

        // println!("writing {:?}", buf);

        let rv = self.stream.write(&buf).expect("Failed to write to socket");
        assert!(rv == idx);

        // read the response length first
        let mut buf = vec![0; 4];
        let rv = self
            .stream
            .read(&mut buf)
            .expect("Failed to read from socket");
        assert!(rv == 4);
        let len = read_u32be(&buf, 0);

        // println!("got back len = {}", len);

        // read the rest of the resposne
        let mut buf = vec![0; len as usize];
        self.stream
            .read_exact(&mut buf)
            .expect("Failed to read from socket");

        // println!("got back {:?}", buf);

        let mut idx = 0;

        // first byte should be the correct response type
        let response_type = read_u8(&buf, idx);
        assert!(response_type == Self::SSH2_AGENT_SIGN_RESPONSE);
        idx += 1;

        // next u32 is ???
        let _foo = read_u32be(&buf, idx);
        idx += 4;

        // read type
        let len = read_u32be(&buf, idx) as usize;
        idx += 4;
        let _t = read_string(&buf, idx, len);
        idx += len;

        // read signed blob
        let len = read_u32be(&buf, idx) as usize;
        idx += 4;
        let blob = &buf[idx..(idx + len)];

        BASE64.encode(&blob)
    }
}

impl fmt::Display for SshAgentClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SshAgentClient: {:?}", self.stream)
    }
}

fn read_u8(buf: &[u8], offset: usize) -> u8 {
    buf[offset]
}

fn write_bytes(buf: &mut [u8], bytes: &[u8], offset: usize) {
    buf[offset..(bytes.len() + offset)].copy_from_slice(bytes);
}

fn write_u32be(buf: &mut [u8], num: u32, offset: usize) {
    buf[offset] = ((num >> 24) % (1 << 8)) as u8;
    buf[offset + 1] = ((num >> 16) % (1 << 8)) as u8;
    buf[offset + 2] = ((num >> 8) % (1 << 8)) as u8;
    buf[offset + 3] = (num % (1 << 8)) as u8;
}

fn write_u8(buf: &mut [u8], num: u8, offset: usize) {
    buf[offset] = num;
}

pub struct SshIdentity {
    pub key_type: String,
    pub comment: String,
    pub md5_fp: String,
    pub sha256_fp: String,
    pub raw_key: Vec<u8>,
    #[allow(dead_code)]
    pub key: String,
}

impl SshIdentity {
    pub fn new(bytes: &[u8], comment: &str) -> SshIdentity {
        // The type of the key is held in the key itself.. extract it here
        let type_len = read_u32be(bytes, 0) as usize;
        let t = read_string(bytes, 4, type_len);

        // generate finger prints
        let md5_fp = md5_fingerprint(bytes);
        let sha256_fp = sha256_fingerprint(bytes);

        SshIdentity {
            raw_key: bytes.to_vec(),
            key: BASE64.encode(&bytes),
            key_type: t,
            comment: comment.to_string(),
            md5_fp,
            sha256_fp,
        }
    }
}

impl fmt::Display for SshIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SshIdentity: {} {} {}",
            self.key_type, self.sha256_fp, self.comment
        )
    }
}

fn sha256_fingerprint(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&bytes);

    let sum = hasher.finalize();

    format!("SHA256:{}", BASE64.encode(&sum))
}

fn md5_fingerprint(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(&bytes);

    let sum = hasher.finalize();
    let strs: Vec<String> = sum.iter().map(|b| format!("{:02x}", b)).collect();

    strs.join(":")
}
