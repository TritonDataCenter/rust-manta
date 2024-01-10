// This code was adapted from tokio's AnyDelimiterCodec
// https://docs.rs/tokio-util/latest/src/tokio_util/codec/any_delimiter_codec.rs.html#41-63
use crate::client::DirectoryEntry;
use std::cmp;
use tokio_util::bytes::{Buf, BytesMut};
use tokio_util::codec::Decoder;

pub struct EntryCodec {
    next_index: usize,
    max_buffer_length: usize,
    is_discarding: bool,
}
impl EntryCodec {
    pub fn new() -> EntryCodec {
        EntryCodec {
            next_index: 0,
            max_buffer_length: usize::MAX,
            is_discarding: false,
        }
    }
    pub fn new_with_max_buffer_length(max_buffer_length: usize) -> EntryCodec {
        EntryCodec {
            next_index: 0,
            max_buffer_length,
            is_discarding: false,
        }
    }
}

/// An error occurred while encoding or decoding a chunk.
#[derive(Debug)]
pub enum EntryCodecError {
    MaxChunkLengthExceeded,
    /// An IO error occurred.
    Io(std::io::Error),
}
impl From<std::io::Error> for EntryCodecError {
    fn from(e: std::io::Error) -> EntryCodecError {
        EntryCodecError::Io(e)
    }
}
impl Decoder for EntryCodec {
    type Item = DirectoryEntry;
    type Error = EntryCodecError;

    fn decode(
        &mut self,
        buf: &mut BytesMut,
    ) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            let read_to =
                cmp::min(self.max_buffer_length.saturating_add(1), buf.len());
            let new_chunk_offset = buf[self.next_index..read_to]
                .iter()
                .position(|b| *b == b'\n');
            match (self.is_discarding, new_chunk_offset) {
                (true, Some(offset)) => {
                    // If we found a new chunk, discard up to that offset and
                    // then stop discarding. On the next iteration, we'll try
                    // to read a chunk normally.
                    buf.advance(offset + self.next_index + 1);
                    self.is_discarding = false;
                    self.next_index = 0;
                }
                (true, None) => {
                    // Otherwise, we didn't find a new chunk, so we'll discard
                    // everything we read. On the next iteration, we'll continue
                    // discarding up to max_len bytes unless we find a new chunk.
                    buf.advance(read_to);
                    self.next_index = 0;
                    if buf.is_empty() {
                        return Ok(None);
                    }
                }
                (false, Some(offset)) => {
                    let new_chunk_index = offset + self.next_index;
                    self.next_index = 0;
                    let mut chunk = buf.split_to(new_chunk_index + 1);
                    chunk.truncate(chunk.len() - 1);
                    let chunk = chunk.freeze();
                    return Ok(Some(serde_json::from_slice(&*chunk).unwrap()));
                }
                (false, None) if buf.len() > self.max_buffer_length => {
                    // Reached the maximum length without finding a
                    // new chunk, return an error and start discarding on the
                    // next call.
                    self.is_discarding = true;
                    return Err(EntryCodecError::MaxChunkLengthExceeded);
                }
                (false, None) => {
                    self.next_index = read_to;
                    return Ok(None);
                }
            }
        }
    }

    fn decode_eof(
        &mut self,
        buf: &mut BytesMut,
    ) -> Result<Option<DirectoryEntry>, EntryCodecError> {
        Ok(match self.decode(buf)? {
            Some(entry) => Some(entry),
            None => {
                // return remaining data, if any
                if buf.is_empty() {
                    None
                } else {
                    let chunk = buf.split_to(buf.len());
                    let chunk = chunk.freeze();
                    self.next_index = 0;
                    return Ok(Some(serde_json::from_slice(&*chunk).unwrap()));
                }
            }
        })
    }
}
