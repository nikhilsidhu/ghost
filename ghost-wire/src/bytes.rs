//! Reading and writing the big-endian, length-prefixed layouts the wire formats share.
//!
//! A format is read front to back and consumed exactly, so bytes a signature or AAD
//! does not cover can never ride along.

use std::fmt;

/// Why a read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The data ends before the field does.
    Truncated,
    /// Bytes remain after the last field.
    Trailing(usize),
    /// A string field is not UTF-8.
    NotUtf8,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::Truncated => f.write_str("truncated"),
            ReadError::Trailing(n) => write!(f, "{n} trailing bytes"),
            ReadError::NotUtf8 => f.write_str("string is not UTF-8"),
        }
    }
}

impl std::error::Error for ReadError {}

/// A cursor over a byte slice.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Whether every byte has been read.
    pub fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        let end = self.pos.checked_add(n).filter(|end| *end <= self.data.len()).ok_or(ReadError::Truncated)?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Everything not read yet.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.data[self.pos..];
        self.pos = self.data.len();
        out
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], ReadError> {
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
    }

    pub fn u8(&mut self) -> Result<u8, ReadError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, ReadError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, ReadError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, ReadError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub fn i32(&mut self) -> Result<i32, ReadError> {
        Ok(i32::from_be_bytes(self.array()?))
    }

    /// Bytes behind a u16 length.
    pub fn prefixed16(&mut self) -> Result<&'a [u8], ReadError> {
        let len = self.u16()? as usize;
        self.take(len)
    }

    /// Bytes behind a u32 length.
    pub fn prefixed32(&mut self) -> Result<&'a [u8], ReadError> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// A string behind a u16 length.
    pub fn string(&mut self) -> Result<String, ReadError> {
        String::from_utf8(self.prefixed16()?.to_vec()).map_err(|_| ReadError::NotUtf8)
    }

    /// Every byte must have been read.
    pub fn finish(self) -> Result<(), ReadError> {
        match self.data.len() - self.pos {
            0 => Ok(()),
            n => Err(ReadError::Trailing(n)),
        }
    }
}

/// Append `bytes` behind a u16 length.
pub fn put_prefixed16(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Append `bytes` behind a u32 length.
pub fn put_prefixed32(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Append a string behind a u16 length.
pub fn put_string(buf: &mut Vec<u8>, s: &str) {
    put_prefixed16(buf, s.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_back_what_was_written() {
        let mut buf = vec![0x07];
        buf.extend_from_slice(&0x0102u16.to_be_bytes());
        buf.extend_from_slice(&0x0304_0506u32.to_be_bytes());
        buf.extend_from_slice(&0x0708_090a_0b0c_0d0eu64.to_be_bytes());
        buf.extend_from_slice(&(-5i32).to_be_bytes());
        buf.extend_from_slice(&[0xAA; 32]);
        put_prefixed16(&mut buf, b"ab");
        put_prefixed32(&mut buf, b"cde");
        put_string(&mut buf, "héllo");
        buf.extend_from_slice(b"tail");

        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 0x07);
        assert_eq!(r.u16().unwrap(), 0x0102);
        assert_eq!(r.u32().unwrap(), 0x0304_0506);
        assert_eq!(r.u64().unwrap(), 0x0708_090a_0b0c_0d0e);
        assert_eq!(r.i32().unwrap(), -5);
        assert_eq!(r.array::<32>().unwrap(), [0xAA; 32]);
        assert_eq!(r.prefixed16().unwrap(), b"ab");
        assert_eq!(r.prefixed32().unwrap(), b"cde");
        assert_eq!(r.string().unwrap(), "héllo");
        assert!(!r.is_empty());
        assert_eq!(r.rest(), b"tail");
        assert!(r.is_empty());
        r.finish().unwrap();
    }

    #[test]
    fn short_data_leftover_bytes_and_bad_strings_are_errors() {
        assert_eq!(Reader::new(&[1, 2, 3]).u32(), Err(ReadError::Truncated));
        assert_eq!(Reader::new(&[0, 5, 1]).prefixed16(), Err(ReadError::Truncated));
        assert_eq!(Reader::new(&[0, 1, 0xFF]).string(), Err(ReadError::NotUtf8));
        let mut r = Reader::new(&[1, 2, 3]);
        r.u8().unwrap();
        assert_eq!(r.finish(), Err(ReadError::Trailing(2)));
    }
}
