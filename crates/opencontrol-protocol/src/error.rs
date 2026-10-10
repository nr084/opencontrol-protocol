use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("incomplete input")]
    Incomplete,
    #[error("invalid length")]
    InvalidLength,
    #[error("resource limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("unsupported wire version: {0}")]
    UnsupportedVersion(u8),
    #[error("cryptographic authentication failed")]
    CryptoFailure,
    #[error("operating system randomness unavailable")]
    Randomness,
    #[error("duplicate, stale or out-of-range sequence")]
    Replay,
    #[error("unexpected message or direction in current state")]
    UnexpectedMessage,
    #[error("decoder is poisoned; create a new decoder")]
    DecoderPoisoned,
}
