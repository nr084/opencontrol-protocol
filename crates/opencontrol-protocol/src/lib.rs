//! Socket-independent codecs for the observed OpenControl Protocol.
//! TLS termination, authentication decisions, clocks and network policy belong to the caller.
//!
//! ```
//! use opencontrol_protocol::*;
//! let limits = ProtocolLimits::default();
//! let mut decoder = ProtocolDecoder::new(limits);
//! let incoming = [0x4b, 5, 0, 22, 4];
//! let mut remaining = incoming.as_slice();
//! while !remaining.is_empty() {
//!     let consumed = decoder.push_bytes(remaining)?;
//!     remaining = &remaining[consumed..];
//!     if let Some(frame) = decoder.next_frame()? {
//!         let message = ControlMessage::decode(frame, WireVersion::V4, limits)?;
//!         assert!(matches!(message, ControlMessage::Version(WireVersion::V4)));
//!     }
//! }
//! decoder.finish()?;
//! let outgoing = ProtocolEncoder::new(limits)
//!     .encode(&ControlMessage::Ok(vec![]), WireVersion::V4)?;
//! assert_eq!(outgoing.as_ref(), &[0x4b, 5, 0, 3, 0]);
//! # Ok::<(), ProtocolError>(())
//! ```
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod control;
pub mod crypto;
pub mod datagram;
mod error;
mod limits;
pub mod routes;
pub mod state;

pub use control::*;
pub use error::ProtocolError;
pub use limits::ProtocolLimits;
pub use routes::{RouteConfiguration, RouteState, RouteUpdate};
pub use state::{Direction, ProtocolState, Role, StateMachine};

/// Version of the compiled protocol library, independent of the wire version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Negotiated wire version; unrelated to the crate version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireVersion {
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
}

impl TryFrom<u8> for WireVersion {
    type Error = ProtocolError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            _ => Err(ProtocolError::UnsupportedVersion(value)),
        }
    }
}
