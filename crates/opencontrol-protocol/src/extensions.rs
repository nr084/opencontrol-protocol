//! Proven control extensions. These do not perform authentication or OS operations.
use crate::{crypto::SessionKey, CipherConfig, ProtocolError, ProtocolLimits, Route};
use bytes::Bytes;
use std::fmt;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Legacy = 0,
    Aes128Gcm = 1,
}
impl TryFrom<u8> for CipherKind {
    type Error = ProtocolError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Legacy),
            1 => Ok(Self::Aes128Gcm),
            _ => Err(ProtocolError::UnsupportedCipher(value)),
        }
    }
}
/// Compile-time legacy feature AND explicit runtime permission are required for encryption.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum LegacyPolicy {
    #[default]
    Disabled,
    ExplicitlyEnabled,
}

pub struct LegacyKey {
    pub(crate) key: SessionKey,
    pub(crate) salt: [u8; 8],
}
impl fmt::Debug for LegacyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LegacyKey([REDACTED])")
    }
}
impl Drop for LegacyKey {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}
impl LegacyKey {
    pub fn from_bytes(key: [u8; 16], salt: [u8; 8]) -> Self {
        Self {
            key: SessionKey::from_bytes(key),
            salt,
        }
    }
    pub fn generate() -> Result<Self, ProtocolError> {
        let mut salt = zeroize::Zeroizing::new([0u8; 8]);
        getrandom::getrandom(&mut salt[..]).map_err(|_| ProtocolError::Randomness)?;
        Ok(Self {
            key: SessionKey::generate()?,
            salt: *salt,
        })
    }
    /// Explicit secret access for a protected control channel only.
    pub fn salt_bytes(&self) -> &[u8; 8] {
        &self.salt
    }
    pub fn key_bytes(&self) -> &[u8; 16] {
        self.key.as_bytes()
    }
}
#[derive(Debug)]
pub struct LegacyCipherConfig {
    pub slot: u8,
    pub key: LegacyKey,
}
#[derive(Debug)]
pub enum AnyCipherConfig {
    Aes(CipherConfig),
    Legacy(LegacyCipherConfig),
}
impl From<CipherConfig> for AnyCipherConfig {
    fn from(c: CipherConfig) -> Self {
        Self::Aes(c)
    }
}
impl AnyCipherConfig {
    pub fn slot(&self) -> u8 {
        match self {
            Self::Aes(c) => c.slot,
            Self::Legacy(c) => c.slot,
        }
    }
    pub fn kind(&self) -> CipherKind {
        match self {
            Self::Aes(_) => CipherKind::Aes128Gcm,
            Self::Legacy(_) => CipherKind::Legacy,
        }
    }
    pub fn duplicate_secret(&self) -> Self {
        match self {
            Self::Aes(c) => Self::Aes(CipherConfig {
                slot: c.slot,
                key: SessionKey::from_bytes(*c.key.as_bytes()),
            }),
            Self::Legacy(c) => Self::Legacy(LegacyCipherConfig {
                slot: c.slot,
                key: LegacyKey::from_bytes(*c.key.key_bytes(), *c.key.salt_bytes()),
            }),
        }
    }
    pub(crate) fn same_material(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        match (self, other) {
            (Self::Aes(a), Self::Aes(b)) => bool::from(a.key.as_bytes().ct_eq(b.key.as_bytes())),
            (Self::Legacy(a), Self::Legacy(b)) => bool::from(
                a.key.key_bytes().ct_eq(b.key.key_bytes()) & a.key.salt.ct_eq(&b.key.salt),
            ),
            _ => false,
        }
    }
    pub(crate) fn decode(p: &[u8]) -> Result<Self, ProtocolError> {
        if p.len() < 2 {
            return Err(ProtocolError::InvalidLength);
        }
        if p[1] > 1 {
            return Err(ProtocolError::InvalidField("cipher slot"));
        }
        match CipherKind::try_from(p[0])? {
            CipherKind::Aes128Gcm => {
                if p.len() != 21 {
                    return Err(ProtocolError::InvalidLength);
                }
                if p[2..5] != [16, 12, 16] {
                    return Err(ProtocolError::InvalidField("AES configuration"));
                }
                let mut key = zeroize::Zeroizing::new([0; 16]);
                key.copy_from_slice(&p[5..]);
                Ok(Self::Aes(CipherConfig {
                    slot: p[1],
                    key: SessionKey::from_bytes(*key),
                }))
            }
            CipherKind::Legacy => {
                if p.len() != 28 {
                    return Err(ProtocolError::InvalidLength);
                }
                if p[2..4] != [16, 8] {
                    return Err(ProtocolError::InvalidField("legacy configuration"));
                }
                let mut key = zeroize::Zeroizing::new([0; 16]);
                key.copy_from_slice(&p[4..20]);
                let mut salt = zeroize::Zeroizing::new([0; 8]);
                salt.copy_from_slice(&p[20..]);
                Ok(Self::Legacy(LegacyCipherConfig {
                    slot: p[1],
                    key: LegacyKey::from_bytes(*key, *salt),
                }))
            }
        }
    }
    pub(crate) fn encode(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, ProtocolError> {
        if self.slot() > 1 {
            return Err(ProtocolError::InvalidField("cipher slot"));
        }
        let mut b = zeroize::Zeroizing::new(vec![self.kind() as u8, self.slot()]);
        match self {
            Self::Aes(c) => {
                b.extend_from_slice(&[16, 12, 16]);
                b.extend_from_slice(c.key.as_bytes());
            }
            Self::Legacy(c) => {
                b.extend_from_slice(&[16, 8]);
                b.extend_from_slice(c.key.key_bytes());
                b.extend_from_slice(c.key.salt_bytes());
            }
        }
        Ok(b)
    }
}

/// These are wire *opcodes*, not the local error-number enum of a reference implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireFailureKind {
    AlreadyConnected = 15,
    License = 20,
    InvalidRequest = 21,
}
#[derive(Clone, PartialEq, Eq)]
pub struct WireFailure {
    pub kind: WireFailureKind,
    pub payload: Bytes,
}
impl fmt::Debug for WireFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireFailure")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteReply {
    pub records: Vec<Route>,
}
/// The old query path has no push flags. An empty R13 is not R14 and may make no progress.
#[derive(Debug)]
pub struct RouteQuery {
    records: Vec<Route>,
    queries: usize,
    limit: usize,
    complete: bool,
    awaiting: bool,
}
impl RouteQuery {
    pub fn new(max_queries: usize) -> Self {
        Self {
            records: Vec::new(),
            queries: 0,
            limit: max_queries.min(4096),
            complete: false,
            awaiting: false,
        }
    }
    pub fn next_request(&mut self) -> Result<crate::ControlMessage, ProtocolError> {
        if self.complete || self.awaiting {
            return Err(ProtocolError::UnexpectedMessage);
        }
        if self.queries >= self.limit {
            return Err(ProtocolError::Limit("route queries"));
        }
        self.queries += 1;
        self.awaiting = true;
        Ok(crate::ControlMessage::RouteRequest)
    }
    pub fn receive(
        &mut self,
        message: &crate::ControlMessage,
        limits: ProtocolLimits,
    ) -> Result<(), ProtocolError> {
        if self.complete || !self.awaiting {
            return Err(ProtocolError::UnexpectedMessage);
        }
        match message {
            crate::ControlMessage::RouteReply(reply) => {
                if reply.records.len() > 255 || reply.records.len() > limits.max_collection_items {
                    return Err(ProtocolError::Limit("route reply"));
                }
                limits.frame(5 + 8 * reply.records.len())?;
                for route in &reply.records {
                    crate::routes::validate(route)?;
                }
                let mut next = self.records.clone();
                for r in &reply.records {
                    if !next.contains(r) {
                        if next.len() >= limits.max_route_entries.min(4096) {
                            return Err(ProtocolError::Limit("route query aggregate"));
                        }
                        next.push(r.clone());
                    }
                }
                self.records = next;
                self.awaiting = false;
                Ok(())
            }
            crate::ControlMessage::NoMoreRoutes => {
                limits.frame(5)?;
                self.complete = true;
                self.awaiting = false;
                Ok(())
            }
            _ => Err(ProtocolError::UnexpectedMessage),
        }
    }
    pub fn complete(&self) -> bool {
        self.complete
    }
    pub fn records(&self) -> &[Route] {
        &self.records
    }
}
