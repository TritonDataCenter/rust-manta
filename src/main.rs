extern crate base64;
extern crate chrono;
extern crate hmac;
extern crate md5;
extern crate serde_json;
extern crate sha2;

use std::env;
use std::time::Duration;
use std::io::prelude::*;
use std::os::unix::net::UnixStream;

use chrono::prelude::*;
use serde_json::Value;
use sha2::Digest;

fn read_u32be(buf: &[u8], offset: usize) -> u32 {
    ((buf[offset + 0] as u32) << 24) +
    ((buf[offset + 1] as u32) << 16) +
    ((buf[offset + 2] as u32) << 8) +
    ((buf[offset + 3] as u32) << 0)
}

fn read_u8(buf: &[u8], offset: usize) -> u8 {
    buf[offset]
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8], offset: usize) {
    for i in 0..bytes.len() {
        buf[i + offset] = bytes[i];
    }
}

fn write_u32be(buf: &mut Vec<u8>, num: u32, offset: usize) {
    buf[offset + 0] = ((num >> 24) % (1 << 8)) as u8;
    buf[offset + 1] = ((num >> 16) % (1 << 8)) as u8;
    buf[offset + 2] = ((num >>  8) % (1 << 8)) as u8;
    buf[offset + 3] = ((num >>  0) % (1 << 8)) as u8;
}

fn write_u8(buf: &mut Vec<u8>, num: u8, offset: usize) {
    buf[offset] = num;
}

fn read_string(buf: &[u8], offset: usize, len: usize) -> String {
    let slice = &buf[offset..(offset + len) as usize];
    String::from_utf8(slice.to_vec()).expect("Failed to read string")
}

fn rfc1123(date: &DateTime<Utc>) -> String {
    date.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn sha256_fingerprint(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::default();
    hasher.input(&bytes);

    let sum = hasher.result();

    format!("SHA256:{}", base64::encode(&sum))
}

fn md5_fingerprint(bytes: &[u8]) -> String {
    let mut hasher = md5::Md5::default();
    hasher.input(&bytes);

    let sum = hasher.result();
    let strs: Vec<String> = sum.iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    strs.join(":")
}

fn auth_header(key_id: String, algorithm: String, signature: String) -> String {
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

    let mut stream = UnixStream::connect(&ssh_auth_sock)
        .expect("failed to connect to socket");

    stream.set_read_timeout(Some(Duration::new(1, 0)))
        .expect("failed to set_read_timeout");

    println!("{:?}", stream);

    // write request for identities
    let buf = [
        0, 0, 0, 1,
        11
    ];
    let rv = stream.write(&buf)
        .expect("Failed to write to socket");
    assert!(rv == 5);

    // read the response length first
    let mut buf = vec![0; 4];
    let rv = stream.read(&mut buf)
        .expect("Failed to read from socket");
    assert!(rv == 4);
    let len = read_u32be(&buf, 0);

    // read the rest of the resposne
    let mut buf = vec![0; len as usize];
    stream.read_exact(&mut buf)
        .expect("Failed to read from socket");

    let mut idx = 0;

    // first byte should be the correct response type
    let response_type = read_u8(&buf, idx);
    assert!(response_type == 12);
    idx = idx + 1;

    // next u32 is the number of keys in the agent
    let num_keys = read_u32be(&buf, idx);
    idx = idx + 4;

    println!("-- found {} keys in ssh-agent --", num_keys);

    // loop each key found
    let mut key_found = false;
    let mut key: Vec<u8> = Vec::new();
    let mut md5_fp = String::new();
    for _ in 0..num_keys {
        // Read key len
        let len = read_u32be(&buf, idx) as usize;
        idx = idx + 4;

        // Extract the bytes for the key
        let bytes = &buf[idx..(idx + len)];

        // The key itself should be base64 encoded
        let _hex = base64::encode(&bytes);

        // The type of the key is held in the key itself.. extract it here
        let type_len = read_u32be(&bytes, 0) as usize;
        let t = read_string(&bytes, 4, type_len);

        idx = idx + len;

        // Read the comment
        let len = read_u32be(&buf, idx) as usize;
        idx = idx + 4;
        let comment = read_string(&buf, idx, len);
        idx = idx + len;

        // sha256 fingerprint
        let sha256_fp = sha256_fingerprint(&bytes);

        // md5 fingerprint
        let _md5_fp = md5_fingerprint(&bytes);

        /*
        println!("type = {}", t);
        println!("key = {}", _hex);
        println!("comment = {}", comment);
        println!("sha256_fp = {}", sha256_fp);
        println!("md5_fp = {}", md5_fp);
        println!();
        */
        println!("{} {} {}", t, sha256_fp, comment);

        if _md5_fp == manta_key_id || sha256_fp == manta_key_id {
            key = bytes.clone().to_vec();
            md5_fp = _md5_fp.clone();
            key_found = true;
        }
    }

    if ! key_found {
        println!("key {} not found in ssh-agent", manta_key_id);
        std::process::exit(1);
    }

    idx = 0;

    //println!("using key = {:?}", key);

    // create request for sign
    let date = rfc1123(&Utc::now());
    let date_header = format!("date: {}", date);
    let data = date_header.as_bytes();
    let mut buf = vec![0; 4 + 1 + 4 + key.len() + 4 + data.len() + 4];

    let len = buf.len() - 4;
    write_u32be(&mut buf, len as u32, idx);
    idx = idx + 4;

    write_u8(&mut buf, 13, idx);
    idx = idx + 1;

    write_u32be(&mut buf, key.len() as u32, idx);
    idx = idx + 4;

    write_bytes(&mut buf, &key, idx);
    idx = idx + key.len();

    write_u32be(&mut buf, data.len() as u32, idx);
    idx = idx + 4;

    write_bytes(&mut buf, &data, idx);
    idx = idx + data.len();

    write_u32be(&mut buf, 0, idx);
    idx = idx + 4;

    // println!("writing {:?}", buf);

    let rv = stream.write(&buf)
        .expect("Failed to write to socket");
    assert!(rv == idx);

    // read the response length first
    let mut buf = vec![0; 4];
    let rv = stream.read(&mut buf)
        .expect("Failed to read from socket");
    assert!(rv == 4);
    let len = read_u32be(&buf, 0);

    // println!("got back len = {}", len);

    // read the rest of the resposne
    let mut buf = vec![0; len as usize];
    stream.read_exact(&mut buf)
        .expect("Failed to read from socket");

    // println!("got back {:?}", buf);

    let mut idx = 0;

    // first byte should be the correct response type
    let response_type = read_u8(&buf, idx);
    assert!(response_type == 14);
    idx = idx + 1;

    // next u32 is ???
    let _foo = read_u32be(&buf, idx);
    idx = idx + 4;

    // read type
    let len = read_u32be(&buf, idx) as usize;
    idx = idx + 4;
    let _t = read_string(&buf, idx, len);
    idx = idx + len;

    // read signed blob
    let len = read_u32be(&buf, idx) as usize;
    idx = idx + 4;
    let blob = &buf[idx..(idx + len)];
    let signature = base64::encode(&blob);

    let key_id = format!("/{}/keys/{}", manta_user, md5_fp);
    let authorization = auth_header(key_id, "rsa-sha1".to_string(), signature);
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
