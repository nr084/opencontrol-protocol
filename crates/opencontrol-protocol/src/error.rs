use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported cipher kind: {0}")]
    UnsupportedCipher(u8),
    #[error("legacy compatibility is disabled")]
    LegacyDisabled,
    #[error("unkeyed legacy checksum failed; this is not a MAC")]
    ChecksumFailure,
    #[error("key/counter exhausted; install a fresh key")]
    KeyExhausted,
    #[error("another local key change is awaiting acknowledgment")]
    RekeyPending,
    #[error("ambiguous simultaneous key changes; reconnect required")]
    RekeyCollision,
    #[error("stale local session event")]
    StaleSession,
    #[error("local session is closed")]
    Closed,
    #[error("monotonic time moved backwards")]
    InvalidTime,
    #[error("unsupported capability: {0}")]
    UnsupportedCapability(&'static str),
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
