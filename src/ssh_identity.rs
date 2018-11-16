extern crate base64;
extern crate chrono;
extern crate hmac;
extern crate md5;
extern crate serde_json;
extern crate sha2;

use std::fmt;

use sha2::Digest;

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
        let type_len = read_u32be(&bytes, 0) as usize;
        let key_type = read_string(&bytes, 4, type_len);

        // generatefinger prints
        let md5_fp = md5_fingerprint(&bytes);
        let sha256_fp = sha256_fingerprint(&bytes);

        SshIdentity {
            raw_key: bytes.to_vec(),
            key: base64::encode(&bytes),
            key_type: key_type,
            comment: comment.to_string(),
            md5_fp: md5_fp,
            sha256_fp: sha256_fp,
        }
    }
}

impl fmt::Display for SshIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SshIdentity: {} {} {}",
           self.key_type, self.sha256_fp, self.comment)
    }
}

fn read_string(buf: &[u8], offset: usize, len: usize) -> String {
    let slice = &buf[offset..(offset + len) as usize];
    String::from_utf8(slice.to_vec()).expect("Failed to read string")
}

fn sha256_fingerprint(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::default();
    hasher.input(&bytes);

    let sum = hasher.result();

    format!("SHA256:{}", base64::encode_config(&sum, base64::STANDARD_NO_PAD))
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

fn read_u32be(buf: &[u8], offset: usize) -> u32 {
    ((buf[offset + 0] as u32) << 24) +
    ((buf[offset + 1] as u32) << 16) +
    ((buf[offset + 2] as u32) << 8) +
    ((buf[offset + 3] as u32) << 0)
}
