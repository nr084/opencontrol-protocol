//! UDP codecs; no socket ownership or endpoint binding policy.
use crate::{
    crypto::{ReplayWindow, SessionKey},
    BindingSecret, ProtocolError, ProtocolLimits, WireVersion,
};
use bytes::Bytes;
use std::fmt;
use zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedData {
    pub unknown_flags_1: u8,
    pub slot: u8,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub ciphertext: Bytes,
}
impl fmt::Debug for EncryptedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedData")
            .field("slot", &self.slot)
            .field("length", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq)]
pub enum Datagram {
    Data(EncryptedData),
    Connect(BindingSecret),
    Keepalive,
    /// Unknown envelope types and noncanonical CONNECT/keepalive envelopes remain lossless.
    Unknown(Bytes),
}
impl fmt::Debug for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(data) => data.fmt(f),
            Self::Connect(_) => f.write_str("Datagram::Connect([REDACTED])"),
            Self::Keepalive => f.write_str("Datagram::Keepalive"),
            Self::Unknown(bytes) => f
                .debug_struct("Datagram::Unknown")
                .field("length", &bytes.len())
                .finish(),
        }
    }
}
impl Datagram {
    pub fn decode(bytes: Bytes, limits: ProtocolLimits) -> Result<Self, ProtocolError> {
        if bytes.len() > limits.max_datagram_size.min(8192) {
            return Err(ProtocolError::Limit("datagram"));
        }
        if bytes.len() < 5 {
            return Err(ProtocolError::Incomplete);
        }
        if bytes[0] != 0x4b {
            return Err(ProtocolError::InvalidField("datagram magic"));
        }
        Ok(match bytes[2] {
            0 => {
                if bytes.len() < 34 {
                    return Err(ProtocolError::InvalidLength);
                }
                if bytes[3] > 1 {
                    return Err(ProtocolError::InvalidField("cipher slot"));
                }
                let mut nonce = [0; 12];
                nonce.copy_from_slice(&bytes[4..16]);
                let mut tag = [0; 16];
                tag.copy_from_slice(&bytes[16..32]);
                Self::Data(EncryptedData {
                    unknown_flags_1: bytes[1],
                    slot: bytes[3],
                    nonce,
                    tag,
                    ciphertext: bytes.slice(32..),
                })
            }
            1 if bytes[..5] == [0x4b, 0, 1, 0, 0] => {
                if bytes.len() != 133 {
                    return Err(ProtocolError::InvalidLength);
                }
                let mut secret = [0; 128];
                secret.copy_from_slice(&bytes[5..]);
                Self::Connect(BindingSecret(secret))
            }
            2 if bytes[..5] == [0x4b, 0, 2, 0, 0] => {
                if bytes.len() != 5 {
                    return Err(ProtocolError::InvalidLength);
                }
                Self::Keepalive
            }
            _ => Self::Unknown(bytes),
        })
    }
    pub fn encode(&self, limits: ProtocolLimits) -> Result<Bytes, ProtocolError> {
        let length = match self {
            Self::Data(d) => d
                .ciphertext
                .len()
                .checked_add(32)
                .ok_or(ProtocolError::InvalidLength)?,
            Self::Connect(_) => 133,
            Self::Keepalive => 5,
            Self::Unknown(b) => b.len(),
        };
        if length > limits.max_datagram_size.min(8192) {
            return Err(ProtocolError::Limit("datagram"));
        }
        let mut b = Vec::with_capacity(length);
        match self {
            Self::Data(d) => {
                if d.slot > 1 || d.ciphertext.len() < 2 {
                    return Err(ProtocolError::InvalidField("data header"));
                }
                b.extend_from_slice(&[0x4b, d.unknown_flags_1, 0, d.slot]);
                b.extend_from_slice(&d.nonce);
                b.extend_from_slice(&d.tag);
                b.extend_from_slice(&d.ciphertext);
            }
            Self::Connect(s) => {
                b.extend_from_slice(&[0x4b, 0, 1, 0, 0]);
                b.extend_from_slice(&s.0);
            }
            Self::Keepalive => b.extend_from_slice(&[0x4b, 0, 2, 0, 0]),
            Self::Unknown(bytes) => {
                if !matches!(Self::decode(bytes.clone(), limits)?, Self::Unknown(_)) {
                    return Err(ProtocolError::InvalidField(
                        "known datagram represented as unknown",
                    ));
                }
                return Ok(bytes.clone());
            }
        }
        Ok(Bytes::from(b))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NetworkPacket {
    pub ether_type: u16,
    pub payload: Bytes,
}
impl fmt::Debug for NetworkPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkPacket")
            .field("ether_type", &self.ether_type)
            .field("length", &self.payload.len())
            .finish()
    }
}

/// One cipher slot, using the same key in both directions. Replacing this object resets counters.
#[derive(Debug)]
pub struct DataCipher {
    key: SessionKey,
    slot: u8,
    version: WireVersion,
    tx_sequence: u32,
    replay: ReplayWindow,
}
impl DataCipher {
    pub fn new(key: SessionKey, slot: u8, version: WireVersion) -> Result<Self, ProtocolError> {
        if slot > 1 {
            return Err(ProtocolError::InvalidField("cipher slot"));
        }
        Ok(Self {
            key,
            slot,
            version,
            tx_sequence: 0,
            replay: ReplayWindow::default(),
        })
    }
    pub fn seal(
        &mut self,
        packet: &NetworkPacket,
        limits: ProtocolLimits,
    ) -> Result<EncryptedData, ProtocolError> {
        let trailer = if self.version == WireVersion::V1 {
            0
        } else {
            4
        };
        let len = packet
            .payload
            .len()
            .checked_add(34 + trailer)
            .ok_or(ProtocolError::InvalidLength)?;
        if len > limits.max_datagram_size.min(8192) {
            return Err(ProtocolError::Limit("datagram"));
        }
        if self.version != WireVersion::V1 && self.tx_sequence >= 0xffff_ffbf {
            return Err(ProtocolError::Replay);
        }
        let mut nonce = [0; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| ProtocolError::Randomness)?;
        let mut plaintext = Vec::with_capacity(len - 32);
        plaintext.extend_from_slice(&packet.ether_type.to_be_bytes());
        plaintext.extend_from_slice(&packet.payload);
        if trailer != 0 {
            self.tx_sequence += 1;
            plaintext.extend_from_slice(&self.tx_sequence.to_be_bytes());
        }
        let result = self.key.encrypt(&nonce, &mut plaintext);
        let tag = match result {
            Ok(tag) => tag,
            Err(e) => {
                plaintext.zeroize();
                return Err(e);
            }
        };
        Ok(EncryptedData {
            unknown_flags_1: 0,
            slot: self.slot,
            nonce,
            tag,
            ciphertext: Bytes::from(plaintext),
        })
    }
    /// Authenticate before updating replay state. Header flag is intentionally not authenticated.
    pub fn open(
        &mut self,
        data: &EncryptedData,
        limits: ProtocolLimits,
    ) -> Result<NetworkPacket, ProtocolError> {
        if data.slot != self.slot {
            return Err(ProtocolError::InvalidField("wrong cipher slot"));
        }
        let len = data
            .ciphertext
            .len()
            .checked_add(32)
            .ok_or(ProtocolError::InvalidLength)?;
        if len > limits.max_datagram_size.min(8192) {
            return Err(ProtocolError::Limit("datagram"));
        }
        let mut plain = data.ciphertext.to_vec();
        if let Err(e) = self.key.decrypt(&data.nonce, &data.tag, &mut plain) {
            plain.zeroize();
            return Err(e);
        }
        let trailer = if self.version == WireVersion::V1 {
            0
        } else {
            4
        };
        if plain.len() < 2 + trailer {
            plain.zeroize();
            return Err(ProtocolError::InvalidLength);
        }
        let end = plain.len() - trailer;
        if trailer != 0 {
            let sequence =
                u32::from_be_bytes([plain[end], plain[end + 1], plain[end + 2], plain[end + 3]]);
            if let Err(e) = self.replay.accept(sequence) {
                plain.zeroize();
                return Err(e);
            }
        }
        let packet = NetworkPacket {
            ether_type: u16::from_be_bytes([plain[0], plain[1]]),
            payload: Bytes::copy_from_slice(&plain[2..end]),
        };
        plain.zeroize();
        Ok(packet)
    }
    pub fn needs_rotation(&self) -> bool {
        self.tx_sequence > 0x0200_0000 || self.replay.last() > 0x0200_0000
    }
}
