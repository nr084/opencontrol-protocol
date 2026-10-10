//! Server-focused ordering validator. I/O, authentication and timers stay with the caller.
use crate::{ControlMessage, ProtocolError, WireVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolState {
    Initial,
    VersionReply,
    Username,
    UsernameResult,
    Password,
    PasswordResult,
    InitialConfig,
    IpConfig,
    UdpBinding,
    Active,
    Closed,
}
#[derive(Debug)]
pub struct StateMachine {
    role: Role,
    state: ProtocolState,
    version: Option<WireVersion>,
    offered: Option<WireVersion>,
    pending_slot: Option<u8>,
    primary_slot: Option<u8>,
}
impl StateMachine {
    pub fn new(role: Role) -> Self {
        Self {
            role,
            state: ProtocolState::Initial,
            version: None,
            offered: None,
            pending_slot: None,
            primary_slot: None,
        }
    }
    pub fn state(&self) -> ProtocolState {
        self.state
    }
    pub fn version(&self) -> Option<WireVersion> {
        self.version
    }
    pub fn primary_slot(&self) -> Option<u8> {
        self.primary_slot
    }
    pub fn pending_slot(&self) -> Option<u8> {
        self.pending_slot
    }
    pub fn close(&mut self) {
        self.state = ProtocolState::Closed;
        self.pending_slot = None;
        self.primary_slot = None;
    }
    pub fn incoming(&mut self, message: &ControlMessage) -> Result<(), ProtocolError> {
        self.observe(
            if self.role == Role::Server {
                Direction::ClientToServer
            } else {
                Direction::ServerToClient
            },
            message,
        )
    }
    pub fn outgoing(&mut self, message: &ControlMessage) -> Result<(), ProtocolError> {
        self.observe(
            if self.role == Role::Server {
                Direction::ServerToClient
            } else {
                Direction::ClientToServer
            },
            message,
        )
    }
    /// Observe both sent and received messages only after codec validation and successful send.
    /// UDP secret matching must precede the server's SecretReceived observation.
    pub fn observe(
        &mut self,
        direction: Direction,
        message: &ControlMessage,
    ) -> Result<(), ProtocolError> {
        use ControlMessage as M;
        use Direction::*;
        use ProtocolState as S;
        let next = match (self.state, direction, message) {
            (S::Initial, ClientToServer, M::Version(v)) => {
                self.offered = Some(*v);
                S::VersionReply
            }
            (S::VersionReply, ServerToClient, M::Version(v)) => {
                if Some(*v as u8) > self.offered.map(|v| v as u8) {
                    return Err(ProtocolError::UnsupportedVersion(*v as u8));
                }
                self.version = Some(*v);
                S::Username
            }
            (S::Username, ClientToServer, M::Username(_)) => S::UsernameResult,
            (S::UsernameResult, ServerToClient, M::Ok(_)) => S::Password,
            (S::Password, ClientToServer, M::Password(_)) => S::PasswordResult,
            (S::PasswordResult, ServerToClient, M::Ok(_)) => S::InitialConfig,
            (S::InitialConfig, ClientToServer, M::InitialConfig(c)) => {
                if c.cipher.slot > 1 {
                    return Err(ProtocolError::InvalidField("cipher slot"));
                }
                self.primary_slot = Some(c.cipher.slot);
                S::IpConfig
            }
            (S::IpConfig, ServerToClient, M::IpConfig(_)) => S::UdpBinding,
            (S::UdpBinding, ServerToClient, M::SecretReceived(_)) => S::Active,
            (
                S::UsernameResult | S::PasswordResult | S::IpConfig | S::UdpBinding,
                ServerToClient,
                M::Error(_),
            ) => S::Closed,
            (S::Active, ClientToServer, M::KeyChange(c)) => {
                if c.slot > 1 {
                    return Err(ProtocolError::InvalidField("cipher slot"));
                }
                self.pending_slot = Some(c.slot);
                S::Active
            }
            (S::Active, ServerToClient, M::KeyChanged(_)) => {
                // Reference behavior permits late and unsolicited acknowledgments.
                if let Some(slot) = self.pending_slot.take() {
                    self.primary_slot = Some(slot);
                }
                S::Active
            }
            (S::Active, ClientToServer, M::KeepaliveRequest)
            | (S::Active, ServerToClient, M::KeepaliveResponse(_) | M::Routes(_) | M::Unknown(_)) => {
                S::Active
            }
            _ => return Err(ProtocolError::UnexpectedMessage),
        };
        self.state = next;
        Ok(())
    }
}
