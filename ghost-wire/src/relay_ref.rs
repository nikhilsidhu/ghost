//! A relay is identified by its Ed25519 verifying key; endpoints are hints
//! that may change. `RelayRef` is the portable form that travels in invite
//! links, pairing codes, recovery codes and `SetHomeRelay` entries.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use thiserror::Error;

use crate::bytes::{put_prefixed16, ReadError, Reader};

pub const RELAY_REF_VERSION: u8 = 0x01;
/// Upper bound on the binary encoding; anything larger is rejected.
pub const RELAY_REF_MAX_BYTES: usize = 512;

const ENDPOINT_KIND_HTTPS: u8 = 0x01;
const ENDPOINT_KIND_IROH: u8 = 0x02;

#[derive(Debug, Error)]
pub enum RelayRefError {
    #[error("relay ref: {0}")]
    Format(String),
}

impl From<ReadError> for RelayRefError {
    fn from(e: ReadError) -> Self {
        RelayRefError::Format(e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// HTTPS base URL, no trailing slash.
    Https(String),
    /// iroh `EndpointAddr`, postcard-encoded; opaque here.
    Iroh(Vec<u8>),
    /// Preserved verbatim so a newer kind survives re-encoding by an older reader.
    Unknown { kind: u8, bytes: Vec<u8> },
}

impl Endpoint {
    fn kind(&self) -> u8 {
        match self {
            Self::Https(_) => ENDPOINT_KIND_HTTPS,
            Self::Iroh(_) => ENDPOINT_KIND_IROH,
            Self::Unknown { kind, .. } => *kind,
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            Self::Https(url) => url.as_bytes(),
            Self::Iroh(bytes) => bytes,
            Self::Unknown { bytes, .. } => bytes,
        }
    }

    fn decode(kind: u8, bytes: &[u8]) -> Result<Self, RelayRefError> {
        match kind {
            ENDPOINT_KIND_HTTPS => {
                let url = std::str::from_utf8(bytes)
                    .map_err(|_| RelayRefError::Format("https endpoint is not utf8".into()))?;
                Ok(Self::Https(url.to_string()))
            }
            ENDPOINT_KIND_IROH => Ok(Self::Iroh(bytes.to_vec())),
            other => Ok(Self::Unknown { kind: other, bytes: bytes.to_vec() }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRef {
    pub relay_vk: [u8; 32],
    pub endpoints: Vec<Endpoint>,
}

impl RelayRef {
    /// A relay reachable at one HTTPS base URL.
    pub fn https(relay_vk: [u8; 32], base_url: &str) -> Self {
        Self {
            relay_vk,
            endpoints: vec![Endpoint::Https(base_url.trim_end_matches('/').to_string())],
        }
    }

    /// A relay known only by key; valid inside a `SetHomeRelay` entry whose
    /// relay the reader already knows.
    pub fn key_only(relay_vk: [u8; 32]) -> Self {
        Self { relay_vk, endpoints: Vec::new() }
    }

    pub fn https_urls(&self) -> impl Iterator<Item = &str> {
        self.endpoints.iter().filter_map(|e| match e {
            Endpoint::Https(url) => Some(url.as_str()),
            _ => None,
        })
    }

    /// First HTTPS endpoint, which the v1 transport dials.
    pub fn primary_https_url(&self) -> Option<&str> {
        self.https_urls().next()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(34 + self.endpoints.len() * 40);
        buf.push(RELAY_REF_VERSION);
        buf.extend_from_slice(&self.relay_vk);
        buf.push(self.endpoints.len() as u8);
        for endpoint in &self.endpoints {
            buf.push(endpoint.kind());
            put_prefixed16(&mut buf, endpoint.payload());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, RelayRefError> {
        if data.len() > RELAY_REF_MAX_BYTES {
            return Err(RelayRefError::Format("too large".into()));
        }
        let mut r = Reader::new(data);
        let version = r.u8()?;
        if version != RELAY_REF_VERSION {
            return Err(RelayRefError::Format(format!("unknown version {version:#x}")));
        }
        let relay_vk = r.array()?;
        let endpoint_count = r.u8()? as usize;
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for _ in 0..endpoint_count {
            let kind = r.u8()?;
            endpoints.push(Endpoint::decode(kind, r.prefixed16()?)?);
        }
        r.finish()?;
        Ok(Self { relay_vk, endpoints })
    }

    /// String form for links and codes: base64url without padding.
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.to_bytes())
    }

    pub fn decode(text: &str) -> Result<Self, RelayRefError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| RelayRefError::Format("invalid base64url".into()))?;
        Self::from_bytes(&bytes)
    }
}

/// Several refs in one body: each as `[len:2][ref bytes]`.
pub fn encode_refs(refs: &[RelayRef]) -> Vec<u8> {
    let mut buf = Vec::new();
    for relay_ref in refs {
        put_prefixed16(&mut buf, &relay_ref.to_bytes());
    }
    buf
}

pub fn decode_refs(data: &[u8]) -> Result<Vec<RelayRef>, RelayRefError> {
    let mut r = Reader::new(data);
    let mut refs = Vec::new();
    while !r.is_empty() {
        refs.push(RelayRef::from_bytes(r.prefixed16()?)?);
    }
    Ok(refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_ref_roundtrips_through_bytes_and_string() {
        let r = RelayRef::https([0x42; 32], "https://relay.example.com/");
        assert_eq!(r.primary_https_url(), Some("https://relay.example.com"));
        let decoded = RelayRef::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(decoded, r);
        let decoded = RelayRef::decode(&r.encode()).unwrap();
        assert_eq!(decoded, r);
    }

    #[test]
    fn key_only_ref_has_no_endpoints() {
        let r = RelayRef::key_only([0x07; 32]);
        let decoded = RelayRef::from_bytes(&r.to_bytes()).unwrap();
        assert!(decoded.endpoints.is_empty());
        assert_eq!(decoded.primary_https_url(), None);
    }

    #[test]
    fn unknown_endpoint_kind_is_preserved() {
        let r = RelayRef {
            relay_vk: [0x11; 32],
            endpoints: vec![
                Endpoint::Unknown { kind: 0x7F, bytes: vec![1, 2, 3] },
                Endpoint::Https("http://127.0.0.1:7700".into()),
                Endpoint::Iroh(vec![9, 9]),
            ],
        };
        let decoded = RelayRef::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(decoded, r);
        assert_eq!(decoded.https_urls().collect::<Vec<_>>(), vec!["http://127.0.0.1:7700"]);
    }

    #[test]
    fn rejects_bad_version_truncation_and_trailing_bytes() {
        let mut bytes = RelayRef::https([0x42; 32], "http://a").to_bytes();
        bytes[0] = 0x02;
        assert!(RelayRef::from_bytes(&bytes).is_err());

        let bytes = RelayRef::https([0x42; 32], "http://a").to_bytes();
        assert!(RelayRef::from_bytes(&bytes[..bytes.len() - 1]).is_err());

        let mut bytes = RelayRef::https([0x42; 32], "http://a").to_bytes();
        bytes.push(0);
        assert!(RelayRef::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_oversized_encoding() {
        let r = RelayRef::https([0x42; 32], &"x".repeat(RELAY_REF_MAX_BYTES));
        assert!(RelayRef::from_bytes(&r.to_bytes()).is_err());
    }
}
