use crate::{crypto::SessionKey, ProtocolError, ProtocolLimits, WireVersion};
use bytes::{Bytes, BytesMut};
use std::fmt;

/// Outer frame. Debug deliberately omits all application bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ControlFrame {
    pub opcode: u8,
    pub payload: Bytes,
}
impl fmt::Debug for ControlFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlFrame")
            .field("opcode", &self.opcode)
            .field("payload_length", &self.payload.len())
            .finish()
    }
}

/// Incremental strict decoder. Invalid input poisons the decoder; it never resynchronizes silently.
/// `push_bytes` fills at most one frame and returns bytes consumed. Drain with `next_frame`
/// before feeding the remainder. This bounds memory even for arbitrarily large input slices.
pub struct ProtocolDecoder {
    buffer: BytesMut,
    limits: ProtocolLimits,
    poisoned: bool,
}
impl Drop for ProtocolDecoder {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buffer.as_mut().zeroize();
    }
}
impl fmt::Debug for ProtocolDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolDecoder")
            .field("buffered_length", &self.buffer.len())
            .field("poisoned", &self.poisoned)
            .finish()
    }
}
impl ProtocolDecoder {
    pub fn new(limits: ProtocolLimits) -> Self {
        Self {
            buffer: BytesMut::new(),
            limits,
            poisoned: false,
        }
    }
    pub fn push_bytes(&mut self, input: &[u8]) -> Result<usize, ProtocolError> {
        if self.poisoned {
            return Err(ProtocolError::DecoderPoisoned);
        }
        let result = self.push_inner(input);
        if result.is_err() {
            self.poisoned = true;
            use zeroize::Zeroize;
            self.buffer.as_mut().zeroize();
            self.buffer.clear();
        }
        result
    }
    fn push_inner(&mut self, mut input: &[u8]) -> Result<usize, ProtocolError> {
        let original = input.len();
        if self.buffer.len() < 4 {
            let n = (4 - self.buffer.len()).min(input.len());
            self.buffer.extend_from_slice(&input[..n]);
            input = &input[n..];
        }
        if !self.buffer.is_empty() && self.buffer[0] != 0x4b {
            return Err(ProtocolError::InvalidField("control magic"));
        }
        if self.buffer.len() >= 3 {
            self.limits
                .frame(u16::from_le_bytes([self.buffer[1], self.buffer[2]]) as usize)?;
        }
        if self.buffer.len() >= 4 {
            let total = u16::from_le_bytes([self.buffer[1], self.buffer[2]]) as usize;
            let n = (total - self.buffer.len()).min(input.len());
            self.buffer.extend_from_slice(&input[..n]);
            input = &input[n..];
        }
        Ok(original - input.len())
    }
    pub fn next_frame(&mut self) -> Result<Option<ControlFrame>, ProtocolError> {
        if self.poisoned {
            return Err(ProtocolError::DecoderPoisoned);
        }
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let total = u16::from_le_bytes([self.buffer[1], self.buffer[2]]) as usize;
        if self.buffer.len() < total {
            return Ok(None);
        }
        let mut bytes = self.buffer.split_to(total).freeze();
        let opcode = bytes[3];
        Ok(Some(ControlFrame {
            opcode,
            payload: bytes.split_off(4),
        }))
    }
    pub fn finish(&self) -> Result<(), ProtocolError> {
        if self.poisoned {
            return Err(ProtocolError::DecoderPoisoned);
        }
        if self.buffer.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::Incomplete)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProtocolEncoder {
    limits: ProtocolLimits,
}
impl ProtocolEncoder {
    pub fn new(limits: ProtocolLimits) -> Self {
        Self { limits }
    }
    pub fn encode_frame(&self, frame: &ControlFrame) -> Result<Bytes, ProtocolError> {
        let total = frame
            .payload
            .len()
            .checked_add(4)
            .ok_or(ProtocolError::InvalidLength)?;
        self.limits.frame(total)?;
        let mut b = BytesMut::with_capacity(total);
        b.extend_from_slice(&[0x4b]);
        b.extend_from_slice(&(total as u16).to_le_bytes());
        b.extend_from_slice(&[frame.opcode]);
        b.extend_from_slice(&frame.payload);
        Ok(b.freeze())
    }
    pub fn encode(
        &self,
        message: &ControlMessage,
        version: WireVersion,
    ) -> Result<Bytes, ProtocolError> {
        self.encode_frame(&message.to_frame(version, self.limits)?)
    }
}

/// Credential bytes have unknown character encoding. No interior NUL is accepted.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential(Bytes);
impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credential([REDACTED])")
    }
}
impl Credential {
    pub fn new(bytes: Bytes, limits: ProtocolLimits) -> Result<Self, ProtocolError> {
        if bytes.len() > limits.max_string_size {
            return Err(ProtocolError::Limit("credential"));
        }
        if bytes.contains(&0) {
            return Err(ProtocolError::InvalidField("interior NUL"));
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Extension {
    pub kind: u8,
    pub value: Bytes,
}
impl fmt::Debug for Extension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extension")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub network: [u8; 4],
    pub netmask: [u8; 4],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routes {
    pub flags: u8,
    pub records: Vec<Route>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMetadata {
    pub version: [u8; 3],
    pub build: u16,
    pub os_code: u32,
    pub description: [u8; 128],
}
#[derive(Debug)]
pub struct CipherConfig {
    pub slot: u8,
    pub key: SessionKey,
}
#[derive(Debug)]
pub struct InitialConfig {
    pub cep: u16,
    pub metadata: Option<ClientMetadata>,
    pub cipher: CipherConfig,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BindingSecret(pub [u8; 128]);
impl fmt::Debug for BindingSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BindingSecret([REDACTED])")
    }
}
impl Drop for BindingSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedIpConfig {
    pub domain: [u8; 256],
    pub wins: [[u8; 4]; 2],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpConfig {
    pub address: [u8; 4],
    pub netmask: [u8; 4],
    pub cep: u16,
    pub dns: [[u8; 4]; 2],
    pub extended: Option<ExtendedIpConfig>,
    pub flags: Option<u8>,
    pub secret: BindingSecret,
}

/// Payloads ignored or insufficiently described by the reference client remain opaque.
pub enum ControlMessage {
    Version(WireVersion),
    Username(Credential),
    Password(Credential),
    Ok(Vec<Extension>),
    Error(Bytes),
    InitialConfig(InitialConfig),
    IpConfig(Box<IpConfig>),
    SecretReceived(Bytes),
    KeyChange(CipherConfig),
    KeyChanged(Bytes),
    KeepaliveRequest,
    KeepaliveResponse(Bytes),
    Routes(Routes),
    Unknown(ControlFrame),
}
impl fmt::Debug for ControlMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlMessage")
            .field("opcode", &self.opcode())
            .finish_non_exhaustive()
    }
}
fn exact(p: &[u8], n: usize) -> Result<(), ProtocolError> {
    if p.len() == n {
        Ok(())
    } else {
        Err(ProtocolError::InvalidLength)
    }
}
fn array<const N: usize>(p: &[u8], offset: usize) -> [u8; N] {
    // Called only after an exact length check in this module.
    let mut a = [0; N];
    a.copy_from_slice(&p[offset..offset + N]);
    a
}
fn decode_cipher(p: &[u8]) -> Result<CipherConfig, ProtocolError> {
    exact(p, 21)?;
    if p[0] != 1 || p[1] > 1 || p[2..5] != [16, 12, 16] {
        return Err(ProtocolError::InvalidField("AES configuration"));
    }
    Ok(CipherConfig {
        slot: p[1],
        key: SessionKey::from_bytes(array(p, 5)),
    })
}
fn encode_cipher(c: &CipherConfig, b: &mut Vec<u8>) -> Result<(), ProtocolError> {
    if c.slot > 1 {
        return Err(ProtocolError::InvalidField("cipher slot"));
    }
    b.extend_from_slice(&[1, c.slot, 16, 12, 16]);
    b.extend_from_slice(c.key.as_bytes());
    Ok(())
}
impl ControlMessage {
    pub fn opcode(&self) -> u8 {
        match self {
            Self::Version(_) => 22,
            Self::Username(_) => 1,
            Self::Password(_) => 2,
            Self::Ok(_) => 3,
            Self::Error(_) => 4,
            Self::InitialConfig(_) => 5,
            Self::IpConfig(_) => 6,
            Self::SecretReceived(_) => 7,
            Self::KeyChange(_) => 8,
            Self::KeyChanged(_) => 9,
            Self::KeepaliveRequest => 10,
            Self::KeepaliveResponse(_) => 11,
            Self::Routes(_) => 19,
            Self::Unknown(f) => f.opcode,
        }
    }
    pub fn decode(
        frame: ControlFrame,
        version: WireVersion,
        limits: ProtocolLimits,
    ) -> Result<Self, ProtocolError> {
        limits.frame(
            frame
                .payload
                .len()
                .checked_add(4)
                .ok_or(ProtocolError::InvalidLength)?,
        )?;
        let p = frame.payload.as_ref();
        Ok(match frame.opcode {
            22 => {
                exact(p, 1)?;
                Self::Version(p[0].try_into()?)
            }
            1 | 2 => {
                if p.last() != Some(&0) {
                    return Err(ProtocolError::InvalidField("credential terminator"));
                }
                let c = Credential::new(frame.payload.slice(..p.len() - 1), limits)?;
                if frame.opcode == 1 {
                    Self::Username(c)
                } else {
                    Self::Password(c)
                }
            }
            3 => {
                let mut rest = p;
                let mut extensions = Vec::new();
                loop {
                    if rest.is_empty() {
                        return Err(ProtocolError::InvalidLength);
                    }
                    let kind = rest[0];
                    rest = &rest[1..];
                    if kind == 0 {
                        if !rest.is_empty() {
                            return Err(ProtocolError::InvalidLength);
                        }
                        break;
                    }
                    if rest.len() < 2 {
                        return Err(ProtocolError::InvalidLength);
                    }
                    let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                    rest = &rest[2..];
                    if len > rest.len() {
                        return Err(ProtocolError::InvalidLength);
                    }
                    if len > limits.max_string_size
                        || extensions.len() >= limits.max_collection_items
                    {
                        return Err(ProtocolError::Limit("OK extensions"));
                    }
                    let start = p.len() - rest.len();
                    extensions.push(Extension {
                        kind,
                        value: frame.payload.slice(start..start + len),
                    });
                    rest = &rest[len..];
                }
                Self::Ok(extensions)
            }
            4 => Self::Error(frame.payload),
            5 => {
                let extended = matches!(version, WireVersion::V3 | WireVersion::V4);
                exact(p, if extended { 160 } else { 23 })?;
                let metadata = extended.then(|| ClientMetadata {
                    version: array(p, 4),
                    build: u16::from_be_bytes(array(p, 7)),
                    os_code: u32::from_be_bytes(array(p, 9)),
                    description: array(p, 13),
                });
                let mut cipher = zeroize::Zeroizing::new(Vec::with_capacity(21));
                cipher.extend_from_slice(&p[2..4]);
                cipher.extend_from_slice(&p[if extended { 141 } else { 4 }..]);
                Self::InitialConfig(InitialConfig {
                    cep: u16::from_be_bytes(array(p, 0)),
                    metadata,
                    cipher: decode_cipher(&cipher)?,
                })
            }
            6 => {
                let (len, secret_offset) = match version {
                    WireVersion::V1 | WireVersion::V2 => (146, 18),
                    WireVersion::V3 => (410, 282),
                    WireVersion::V4 => (411, 283),
                };
                exact(p, len)?;
                Self::IpConfig(Box::new(IpConfig {
                    address: array(p, 0),
                    netmask: array(p, 4),
                    cep: u16::from_be_bytes(array(p, 8)),
                    dns: [array(p, 10), array(p, 14)],
                    extended: (secret_offset > 18).then(|| ExtendedIpConfig {
                        domain: array(p, 18),
                        wins: [array(p, 274), array(p, 278)],
                    }),
                    flags: (version == WireVersion::V4).then(|| p[282]),
                    secret: BindingSecret(array(p, secret_offset)),
                }))
            }
            7 => Self::SecretReceived(frame.payload),
            8 => Self::KeyChange(decode_cipher(p)?),
            9 => Self::KeyChanged(frame.payload),
            10 => {
                if p != [0] {
                    return Err(ProtocolError::InvalidField("keepalive request"));
                }
                Self::KeepaliveRequest
            }
            11 => Self::KeepaliveResponse(frame.payload),
            19 => {
                if p.len() < 2 {
                    return Err(ProtocolError::InvalidLength);
                }
                exact(p, 2 + 8 * p[1] as usize)?;
                if p[1] as usize > limits.max_collection_items {
                    return Err(ProtocolError::Limit("routes"));
                }
                Self::Routes(Routes {
                    flags: p[0],
                    records: p[2..]
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|r| Route {
                            network: array(r, 0),
                            netmask: array(r, 4),
                        })
                        .collect(),
                })
            }
            _ => Self::Unknown(frame),
        })
    }
    pub fn to_frame(
        &self,
        version: WireVersion,
        limits: ProtocolLimits,
    ) -> Result<ControlFrame, ProtocolError> {
        let mut p = zeroize::Zeroizing::new(Vec::new());
        match self {
            Self::Version(v) => p.push(*v as u8),
            Self::Username(c) | Self::Password(c) => {
                if c.0.len() > limits.max_string_size {
                    return Err(ProtocolError::Limit("credential"));
                }
                p.extend_from_slice(&c.0);
                p.push(0);
            }
            Self::Ok(extensions) => {
                if extensions.len() > limits.max_collection_items {
                    return Err(ProtocolError::Limit("OK extensions"));
                }
                for e in extensions {
                    if e.kind == 0 {
                        return Err(ProtocolError::InvalidField("TLV kind"));
                    }
                    if e.value.len() > limits.max_string_size || e.value.len() > u16::MAX as usize {
                        return Err(ProtocolError::Limit("TLV value"));
                    }
                    let next = p
                        .len()
                        .checked_add(3 + e.value.len() + 1)
                        .ok_or(ProtocolError::InvalidLength)?;
                    limits.frame(next + 4)?;
                    p.push(e.kind);
                    p.extend_from_slice(&(e.value.len() as u16).to_be_bytes());
                    p.extend_from_slice(&e.value);
                }
                p.push(0);
            }
            Self::Error(b)
            | Self::SecretReceived(b)
            | Self::KeyChanged(b)
            | Self::KeepaliveResponse(b) => {
                limits.frame(b.len().checked_add(4).ok_or(ProtocolError::InvalidLength)?)?;
                p.extend_from_slice(b);
            }
            Self::InitialConfig(c) => {
                p.extend_from_slice(&c.cep.to_be_bytes());
                let mut cipher = zeroize::Zeroizing::new(Vec::new());
                encode_cipher(&c.cipher, &mut cipher)?;
                p.extend_from_slice(&cipher[..2]);
                match (version, &c.metadata) {
                    (WireVersion::V1 | WireVersion::V2, None) => (),
                    (WireVersion::V3 | WireVersion::V4, Some(m)) => {
                        p.extend_from_slice(&m.version);
                        p.extend_from_slice(&m.build.to_be_bytes());
                        p.extend_from_slice(&m.os_code.to_be_bytes());
                        p.extend_from_slice(&m.description);
                    }
                    _ => return Err(ProtocolError::InvalidField("metadata for version")),
                }
                p.extend_from_slice(&cipher[2..]);
            }
            Self::IpConfig(c) => {
                p.extend_from_slice(&c.address);
                p.extend_from_slice(&c.netmask);
                p.extend_from_slice(&c.cep.to_be_bytes());
                for a in c.dns {
                    p.extend_from_slice(&a);
                }
                match (version, &c.extended, c.flags) {
                    (WireVersion::V1 | WireVersion::V2, None, None) => (),
                    (WireVersion::V3, Some(e), None) | (WireVersion::V4, Some(e), Some(_)) => {
                        p.extend_from_slice(&e.domain);
                        for a in e.wins {
                            p.extend_from_slice(&a);
                        }
                        if let Some(f) = c.flags {
                            p.push(f);
                        }
                    }
                    _ => return Err(ProtocolError::InvalidField("IP config for version")),
                }
                p.extend_from_slice(&c.secret.0);
            }
            Self::KeyChange(c) => encode_cipher(c, &mut p)?,
            Self::KeepaliveRequest => p.push(0),
            Self::Routes(r) => {
                if r.records.len() > 255 || r.records.len() > limits.max_collection_items {
                    return Err(ProtocolError::Limit("routes"));
                }
                p.extend_from_slice(&[r.flags, r.records.len() as u8]);
                for r in &r.records {
                    p.extend_from_slice(&r.network);
                    p.extend_from_slice(&r.netmask);
                }
            }
            Self::Unknown(f) => {
                if matches!(f.opcode, 1..=11 | 19 | 22) {
                    return Err(ProtocolError::InvalidField(
                        "known opcode represented as unknown",
                    ));
                }
                limits.frame(
                    f.payload
                        .len()
                        .checked_add(4)
                        .ok_or(ProtocolError::InvalidLength)?,
                )?;
                return Ok(f.clone());
            }
        }
        limits.frame(p.len() + 4)?;
        Ok(ControlFrame {
            opcode: self.opcode(),
            payload: Bytes::from(std::mem::take(&mut *p)),
        })
    }
}
