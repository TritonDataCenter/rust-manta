extern crate base64;
extern crate chrono;
extern crate hmac;
extern crate md5;
extern crate serde_json;
extern crate sha2;

use std::fmt;
use std::time::Duration;
use std::io::prelude::*;
use std::os::unix::net::UnixStream;

use ssh_identity::SshIdentity;

//mod ssh_identity;

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

        stream.set_read_timeout(Some(Duration::new(1, 0)))
            .expect("failed to set_read_timeout");

        SshAgentClient {
            socket_path: socket_path.to_string(),
            stream: stream
        }
    }

    pub fn list_identities(&mut self) -> Vec<SshIdentity> {
        let mut identities: Vec<SshIdentity> = Vec::new();

        // write request for identities
        let buf = [
            0, 0, 0, 1,
            Self::SSH_AGENTC_REQUEST_RSA_IDENTITIES
        ];
        let rv = self.stream.write(&buf)
            .expect("Failed to write to socket");
        assert!(rv == 5);

        // read the response length first
        let mut buf = vec![0; 4];
        let rv = self.stream.read(&mut buf)
            .expect("Failed to read from socket");
        assert!(rv == 4);
        let len = read_u32be(&buf, 0);

        // read the rest of the resposne
        let mut buf = vec![0; len as usize];
        self.stream.read_exact(&mut buf)
            .expect("Failed to read from socket");

        let mut idx = 0;

        // first byte should be the correct response type
        let response_type = read_u8(&buf, idx);
        assert!(response_type == Self::SSH_AGENT_IDENTITIES_ANSWER);
        idx = idx + 1;

        // next u32 is the number of keys in the agent
        let num_keys = read_u32be(&buf, idx);
        idx = idx + 4;

        // loop each key found
        for _ in 0..num_keys {
            // Read key len
            let len = read_u32be(&buf, idx) as usize;
            idx = idx + 4;

            // Extract the bytes for the key
            let bytes = &buf[idx..(idx + len)];
            idx = idx + len;

            // Read the comment
            let len = read_u32be(&buf, idx) as usize;
            idx = idx + 4;
            let comment = read_string(&buf, idx, len);
            idx = idx + len;

            // Make a new SshIdentity
            let ident = SshIdentity::new(bytes, &comment);
            identities.push(ident);
        }

        identities
    }

    pub fn sign_data(&mut self, identity: &SshIdentity, data: &[u8]) -> String {
        let mut idx = 0;
        let mut buf = vec![0; 4 + 1 + 4 + identity.raw_key.len() + 4 + data.len() + 4];

        let len = buf.len() - 4;
        write_u32be(&mut buf, len as u32, idx);
        idx = idx + 4;

        write_u8(&mut buf, Self::SSH2_AGENTC_SIGN_REQUEST, idx);
        idx = idx + 1;

        write_u32be(&mut buf, identity.raw_key.len() as u32, idx);
        idx = idx + 4;

        write_bytes(&mut buf, &identity.raw_key, idx);
        idx = idx + identity.raw_key.len();

        write_u32be(&mut buf, data.len() as u32, idx);
        idx = idx + 4;

        write_bytes(&mut buf, &data, idx);
        idx = idx + data.len();

        write_u32be(&mut buf, 0, idx);
        idx = idx + 4;

        // println!("writing {:?}", buf);

        let rv = self.stream.write(&buf)
            .expect("Failed to write to socket");
        assert!(rv == idx);

        // read the response length first
        let mut buf = vec![0; 4];
        let rv = self.stream.read(&mut buf)
            .expect("Failed to read from socket");
        assert!(rv == 4);
        let len = read_u32be(&buf, 0);

        // println!("got back len = {}", len);

        // read the rest of the resposne
        let mut buf = vec![0; len as usize];
        self.stream.read_exact(&mut buf)
            .expect("Failed to read from socket");

        // println!("got back {:?}", buf);

        let mut idx = 0;

        // first byte should be the correct response type
        let response_type = read_u8(&buf, idx);
        assert!(response_type == Self::SSH2_AGENT_SIGN_RESPONSE);
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

        base64::encode(&blob)
    }
}

impl fmt::Display for SshAgentClient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SshAgentClient: {:?}", self.stream)
    }
}

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
