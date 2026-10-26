//! Separate certificate-selected endpoint protocol. The transport establishes role/trust.
use crate::{AnyCipherConfig, BindingSecret, ControlMessage, ProtocolError, WireVersion};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpConfig1 {
    pub address: [u8; 4],
    pub netmask: [u8; 4],
}
impl IpConfig1 {
    pub(crate) fn decode(p: &[u8]) -> Result<Self, ProtocolError> {
        if p.len() != 8 {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(Self {
            address: arr(p, 0),
            netmask: arr(p, 4),
        })
    }
    pub(crate) fn encode(&self) -> Vec<u8> {
        [self.address, self.netmask].concat()
    }
}
#[derive(Debug)]
pub enum IpConfig2 {
    Accepted {
        address: [u8; 4],
        netmask: [u8; 4],
        cep: u16,
        cipher: AnyCipherConfig,
    },
    /// No successful cipher installation exists in this branch.
    Rejected {
        address: [u8; 4],
        netmask: [u8; 4],
        error: u8,
        cep: u16,
        unknown_kind: u8,
        unknown_slot: u8,
    },
}
impl IpConfig2 {
    pub(crate) fn decode(p: &[u8]) -> Result<Self, ProtocolError> {
        if p.len() < 13 {
            return Err(ProtocolError::InvalidLength);
        }
        let address = arr(p, 0);
        let netmask = arr(p, 4);
        let cep = u16::from_be_bytes(arr(p, 9));
        if p[8] == 0 {
            Ok(Self::Accepted {
                address,
                netmask,
                cep,
                cipher: AnyCipherConfig::decode(&p[11..])?,
            })
        } else {
            if p.len() != 13 {
                return Err(ProtocolError::InvalidLength);
            }
            Ok(Self::Rejected {
                address,
                netmask,
                error: p[8],
                cep,
                unknown_kind: p[11],
                unknown_slot: p[12],
            })
        }
    }
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let mut b = Zeroizing::new(Vec::new());
        match self {
            Self::Accepted {
                address,
                netmask,
                cep,
                cipher,
            } => {
                b.extend_from_slice(address);
                b.extend_from_slice(netmask);
                b.push(0);
                b.extend_from_slice(&cep.to_be_bytes());
                b.extend_from_slice(&cipher.encode()?);
            }
            Self::Rejected {
                address,
                netmask,
                error,
                cep,
                unknown_kind,
                unknown_slot,
            } => {
                if *error == 0 {
                    return Err(ProtocolError::InvalidField("S2S rejection code"));
                }
                b.extend_from_slice(address);
                b.extend_from_slice(netmask);
                b.push(*error);
                b.extend_from_slice(&cep.to_be_bytes());
                b.extend_from_slice(&[*unknown_kind, *unknown_slot]);
            }
        }
        Ok(b)
    }
}
#[derive(Debug)]
pub struct IpConfig3 {
    pub cep: u16,
    pub secret: BindingSecret,
}
impl IpConfig3 {
    pub(crate) fn decode(p: &[u8]) -> Result<Self, ProtocolError> {
        if p.len() != 130 {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(Self {
            cep: u16::from_be_bytes(arr(p, 0)),
            secret: BindingSecret(arr(p, 2)),
        })
    }
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut b = Zeroizing::new(self.cep.to_be_bytes().to_vec());
        b.extend_from_slice(&self.secret.0);
        b
    }
}
fn arr<const N: usize>(p: &[u8], i: usize) -> [u8; N] {
    let mut a = [0; N];
    a.copy_from_slice(&p[i..i + N]);
    a
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    Initiator,
    Acceptor,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Incoming,
    Outgoing,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
    VersionOffer,
    VersionReply,
    Config1,
    Config2,
    Config3,
    Binding,
    Active,
    Closed,
}
#[derive(Debug, Clone)]
pub struct EndpointMachine {
    role: EndpointRole,
    state: EndpointState,
    version: Option<WireVersion>,
    offered: Option<WireVersion>,
    local_pending: Option<u8>,
    remote_pending: Option<u8>,
    primary: Option<u8>,
}
impl EndpointMachine {
    pub fn new(role: EndpointRole) -> Self {
        Self {
            role,
            state: EndpointState::VersionOffer,
            version: None,
            offered: None,
            local_pending: None,
            remote_pending: None,
            primary: None,
        }
    }
    pub fn state(&self) -> EndpointState {
        self.state
    }
    pub fn version(&self) -> Option<WireVersion> {
        self.version
    }
    pub fn primary_slot(&self) -> Option<u8> {
        self.primary
    }
    pub fn local_pending(&self) -> Option<u8> {
        self.local_pending
    }
    pub fn remote_pending(&self) -> Option<u8> {
        self.remote_pending
    }
    pub fn close(&mut self) {
        self.state = EndpointState::Closed;
        self.local_pending = None;
        self.remote_pending = None;
        self.primary = None;
    }
    pub fn observe(&mut self, flow: Flow, message: &ControlMessage) -> Result<(), ProtocolError> {
        use ControlMessage as M;
        use EndpointState as S;
        if self.state == S::Closed {
            return Err(ProtocolError::Closed);
        }
        if matches!(message, M::Failure(_)) {
            self.close();
            return Ok(());
        }
        let from_acceptor = matches!(
            (self.role, flow),
            (EndpointRole::Initiator, Flow::Incoming) | (EndpointRole::Acceptor, Flow::Outgoing)
        );
        let next = match (self.state, from_acceptor, message) {
            (S::VersionOffer, true, M::Version(v)) => {
                self.offered = Some(*v);
                S::VersionReply
            }
            (S::VersionReply, false, M::Version(v)) => {
                if Some(*v as u8) > self.offered.map(|v| v as u8) {
                    return Err(ProtocolError::UnsupportedVersion(*v as u8));
                }
                self.version = Some(*v);
                S::Config1
            }
            (S::Config1, true, M::S2sConfig1(_)) => S::Config2,
            (S::Config2, false, M::S2sConfig2(IpConfig2::Accepted { cipher, .. })) => {
                if cipher.slot() > 1 {
                    return Err(ProtocolError::InvalidField("cipher slot"));
                }
                self.primary = Some(cipher.slot());
                S::Config3
            }
            (S::Config2, false, M::S2sConfig2(IpConfig2::Rejected { .. })) => {
                self.close();
                return Ok(());
            }
            (S::Config3, true, M::S2sConfig3(_)) => S::Binding,
            (S::Binding, true, M::SecretReceived(_)) => S::Active,
            (S::Active, _, M::KeepaliveRequest | M::Routes(_)) => S::Active,
            (S::Active, _, M::KeyChange(c)) => {
                self.proposal(flow, c.slot)?;
                S::Active
            }
            (S::Active, _, M::LegacyKeyChange(c)) => {
                self.proposal(flow, c.slot)?;
                S::Active
            }
            (S::Active, _, M::KeyChanged(_)) => {
                let pending = if flow == Flow::Incoming {
                    &mut self.local_pending
                } else {
                    &mut self.remote_pending
                };
                if let Some(slot) = pending.take() {
                    self.primary = Some(slot);
                }
                S::Active
            }
            _ => return Err(ProtocolError::UnexpectedMessage),
        };
        self.state = next;
        Ok(())
    }
    fn proposal(&mut self, flow: Flow, slot: u8) -> Result<(), ProtocolError> {
        if slot > 1 {
            return Err(ProtocolError::InvalidField("cipher slot"));
        }
        if flow == Flow::Outgoing && self.primary == Some(slot) {
            return Err(ProtocolError::InvalidField("secondary slot required"));
        }
        let (own, other) = if flow == Flow::Outgoing {
            (&mut self.local_pending, self.remote_pending)
        } else {
            (&mut self.remote_pending, self.local_pending)
        };
        if other.is_some() {
            return Err(ProtocolError::RekeyCollision);
        }
        if own.is_some() {
            return Err(ProtocolError::RekeyPending);
        }
        *own = Some(slot);
        Ok(())
    }
}
