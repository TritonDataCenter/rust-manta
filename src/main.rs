extern crate base64;
extern crate chrono;
extern crate hmac;
extern crate md5;
extern crate serde_json;
extern crate sha2;

use std::env;

use chrono::prelude::*;
use serde_json::Value;

mod ssh_agent_client;
mod ssh_identity;

use ssh_agent_client::SshAgentClient;

fn rfc1123(date: &DateTime<Utc>) -> String {
    date.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn auth_header(key_id: &str, algorithm: &str, signature: &str) -> String {
    format!("Signature keyId=\"{}\",algorithm=\"{}\",headers=\"date\",signature=\"{}\"",
        key_id, algorithm, signature)
}

fn main() {
    let ssh_auth_sock = env::var("SSH_AUTH_SOCK")
        .expect("SSH_AUTH_SOCK not set");
    let manta_key_id = env::var("MANTA_KEY_ID")
        .expect("MANTA_KEY_ID not set");
    let manta_user = env::var("MANTA_USER")
        .expect("MANTA_USER not set");
    let manta_url = env::var("MANTA_URL")
        .expect("MANTA_URL not set");

    assert!(!ssh_auth_sock.is_empty());
    assert!(!manta_key_id.is_empty());
    assert!(!manta_user.is_empty());
    assert!(!manta_url.is_empty());

    let args: Vec<String> = env::args().collect();
    let args = &args[1..]; // chop off 1st arg (program name)
    let mut loc = match args.len() {
        0 => format!("/{}/stor", manta_user),
        _ => args[0].clone(),
    };
    if loc.starts_with("~~/") {
        loc = format!("/{}/{}", manta_user, &loc[3..]);
    }
    assert!(loc.starts_with('/'));

    println!("{:?}", loc);

    println!("ssh_auth_sock = {}", ssh_auth_sock);
    println!("manta_key_id = {}", manta_key_id);

    let mut ssh_agent_client = SshAgentClient::new(&ssh_auth_sock);
    let identities = ssh_agent_client.list_identities();

    println!("found {} ssh identities", identities.len());
    let idx = identities.iter().position( |ref ident| {
        ident.md5_fp == manta_key_id || ident.sha256_fp == manta_key_id
    }).expect("Failed to find key in ssh-agent");

    let identity = &identities[idx];
    println!("{}", identity);

    // create request for sign
    let date = rfc1123(&Utc::now());
    let date_header = format!("date: {}", date);
    let data = date_header.as_bytes();
    let signature = ssh_agent_client.sign_data(identity, data);

    let key_id = format!("/{}/keys/{}", manta_user, identity.md5_fp);
    let authorization = auth_header(&key_id, "rsa-sha1", &signature);
    println!();
    println!("curl -sS --header '{}' --header 'authorization: {}' '{}{}';echo",
         date_header, authorization, manta_url, loc);
    println!();

    // TODO find an HTTP(s) client library that works on SmartOS
    let output = std::process::Command::new("curl")
                                       .arg("-sS")
                                       .arg("--header")
                                       .arg(format!("{}", date_header))
                                       .arg("--header")
                                       .arg(format!("authorization: {}", authorization))
                                       .arg(format!("{}{}", manta_url, loc))
                                       .output()
                                       .expect("failed to execute curl");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let files = stdout.trim().split("\n");

    // Parse each blob
    for file in files {
        let obj: Value = serde_json::from_str(file).expect("Failed to parse JSON");
        let slash = if obj["type"] == "directory" { "/" } else { "" };
        let name = obj["name"].as_str().expect("Failed to extract name");
        println!("{}{}", name, slash);
    }
}
