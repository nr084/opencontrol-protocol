//! Local epoch fencing and two-slot crypto. No event token or generation is a wire field.
use crate::{
    datagram::{DataCipher, Datagram, NetworkPacket},
    AnyCipherConfig, CipherKind, LegacyPolicy, ProtocolError, ProtocolLimits, WireVersion,
};
use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionEpoch([u8; 16]);
impl SessionEpoch {
    pub fn generate() -> Result<Self, ProtocolError> {
        let mut id = [0; 16];
        getrandom::getrandom(&mut id).map_err(|_| ProtocolError::Randomness)?;
        Ok(Self(id))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrity {
    Authenticated,
    UnkeyedChecksum,
    NoIntegrity,
}
#[derive(Debug, PartialEq, Eq)]
pub struct DecodedPacket {
    pub packet: NetworkPacket,
    pub integrity: Integrity,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckOutcome {
    Promoted { slot: u8, generation: u64 },
    IgnoredUnsolicited,
}
#[derive(Debug)]
enum Cipher {
    Aes(DataCipher),
    #[cfg(feature = "legacy")]
    Legacy(Box<crate::legacy::LegacyDataCipher>),
}
#[derive(Debug)]
struct Slot {
    material: AnyCipherConfig,
    cipher: Cipher,
    generation: u64,
}
#[derive(Debug)]
pub struct KeySlots {
    epoch: SessionEpoch,
    version: WireVersion,
    policy: LegacyPolicy,
    slots: [Option<Slot>; 2],
    generations: [u64; 2],
    primary: Option<u8>,
    local_pending: Option<u8>,
    remote_pending: Option<u8>,
    closed: bool,
}
impl KeySlots {
    pub fn new(version: WireVersion, policy: LegacyPolicy) -> Result<Self, ProtocolError> {
        Ok(Self {
            epoch: SessionEpoch::generate()?,
            version,
            policy,
            slots: [None, None],
            generations: [0; 2],
            primary: None,
            local_pending: None,
            remote_pending: None,
            closed: false,
        })
    }
    pub fn epoch(&self) -> SessionEpoch {
        self.epoch
    }
    pub(crate) fn set_version(&mut self, version: WireVersion) -> Result<(), ProtocolError> {
        if self.primary.is_some() {
            return Err(ProtocolError::UnexpectedMessage);
        }
        self.version = version;
        Ok(())
    }
    pub fn primary_slot(&self) -> Option<u8> {
        self.primary
    }
    pub fn pending_slot(&self) -> Option<u8> {
        self.local_pending
    }
    pub fn peer_pending_slot(&self) -> Option<u8> {
        self.remote_pending
    }
    pub fn generation(&self, slot: u8) -> Option<u64> {
        self.slots
            .get(slot as usize)
            .and_then(Option::as_ref)
            .map(|s| s.generation)
    }
    fn check(&self, epoch: SessionEpoch) -> Result<(), ProtocolError> {
        if epoch != self.epoch {
            return Err(ProtocolError::StaleSession);
        }
        if self.closed {
            return Err(ProtocolError::Closed);
        }
        Ok(())
    }
    fn build(&self, config: &AnyCipherConfig) -> Result<Slot, ProtocolError> {
        let slot = config.slot() as usize;
        if slot > 1 {
            return Err(ProtocolError::InvalidField("cipher slot"));
        }
        if self
            .slots
            .iter()
            .flatten()
            .any(|s| s.material.same_material(config))
        {
            return Err(ProtocolError::InvalidField("reused key material"));
        }
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(ProtocolError::KeyExhausted)?;
        let cipher = match config {
            AnyCipherConfig::Aes(c) => Cipher::Aes(DataCipher::new(
                crate::crypto::SessionKey::from_bytes(*c.key.as_bytes()),
                c.slot,
                self.version,
            )?),
            AnyCipherConfig::Legacy(_) => {
                if self.policy != LegacyPolicy::ExplicitlyEnabled {
                    return Err(ProtocolError::LegacyDisabled);
                }
                #[cfg(feature = "legacy")]
                {
                    let AnyCipherConfig::Legacy(c) = config else {
                        return Err(ProtocolError::LegacyDisabled);
                    };
                    Cipher::Legacy(Box::new(crate::legacy::LegacyDataCipher::new(
                        c,
                        self.version,
                        self.policy,
                    )?))
                }
                #[cfg(not(feature = "legacy"))]
                {
                    return Err(ProtocolError::LegacyDisabled);
                }
            }
        };
        Ok(Slot {
            material: config.duplicate_secret(),
            cipher,
            generation,
        })
    }
    fn commit(&mut self, config: &AnyCipherConfig, candidate: Slot) {
        let i = config.slot() as usize;
        self.generations[i] = candidate.generation;
        self.slots[i] = Some(candidate);
    }
    pub fn install_initial(
        &mut self,
        epoch: SessionEpoch,
        config: &AnyCipherConfig,
    ) -> Result<(), ProtocolError> {
        self.check(epoch)?;
        if self.primary.is_some() {
            return Err(ProtocolError::UnexpectedMessage);
        }
        let candidate = self.build(config)?;
        self.commit(config, candidate);
        self.primary = Some(config.slot());
        Ok(())
    }
    /// One local proposal at a time. Never retransmit an identical key or invent an ACK ID.
    pub fn propose(
        &mut self,
        epoch: SessionEpoch,
        config: &AnyCipherConfig,
    ) -> Result<(), ProtocolError> {
        self.stage(epoch, config, true)
    }
    /// Caller sends R9 only after successful installation, then calls acknowledge_peer.
    pub fn receive_proposal(
        &mut self,
        epoch: SessionEpoch,
        config: &AnyCipherConfig,
    ) -> Result<(), ProtocolError> {
        self.stage(epoch, config, false)
    }
    fn stage(
        &mut self,
        epoch: SessionEpoch,
        config: &AnyCipherConfig,
        local: bool,
    ) -> Result<(), ProtocolError> {
        self.check(epoch)?;
        let (own, other) = if local {
            (self.local_pending, self.remote_pending)
        } else {
            (self.remote_pending, self.local_pending)
        };
        if other.is_some() {
            return Err(ProtocolError::RekeyCollision);
        }
        if own.is_some() {
            return Err(ProtocolError::RekeyPending);
        }
        if self.primary.is_none() || (local && self.primary == Some(config.slot())) {
            return Err(ProtocolError::InvalidField("secondary slot required"));
        }
        let candidate = self.build(config)?;
        self.commit(config, candidate);
        if local {
            self.local_pending = Some(config.slot())
        } else {
            self.remote_pending = Some(config.slot())
        }
        Ok(())
    }
    pub fn acknowledge_local(&mut self, epoch: SessionEpoch) -> Result<AckOutcome, ProtocolError> {
        self.ack(epoch, true)
    }
    pub fn acknowledge_peer(&mut self, epoch: SessionEpoch) -> Result<AckOutcome, ProtocolError> {
        self.ack(epoch, false)
    }
    fn ack(&mut self, epoch: SessionEpoch, local: bool) -> Result<AckOutcome, ProtocolError> {
        self.check(epoch)?;
        let pending = if local {
            self.local_pending
        } else {
            self.remote_pending
        };
        let Some(slot) = pending else {
            return Ok(AckOutcome::IgnoredUnsolicited);
        };
        let generation = self
            .generation(slot)
            .ok_or(ProtocolError::UnexpectedMessage)?;
        self.primary = Some(slot);
        if local {
            self.local_pending = None
        } else {
            self.remote_pending = None
        }
        Ok(AckOutcome::Promoted { slot, generation })
    }
    pub fn seal(
        &mut self,
        epoch: SessionEpoch,
        packet: &NetworkPacket,
        limits: ProtocolLimits,
    ) -> Result<Bytes, ProtocolError> {
        self.check(epoch)?;
        let primary = self.primary.ok_or(ProtocolError::UnexpectedMessage)? as usize;
        // The native initiator may replace the currently selected slot. Receive the
        // new generation immediately, but never send its data before R9 is written.
        if self.remote_pending == Some(primary as u8) {
            return Err(ProtocolError::RekeyPending);
        }
        let slot = self.slots[primary]
            .as_mut()
            .ok_or(ProtocolError::UnexpectedMessage)?;
        match &mut slot.cipher {
            Cipher::Aes(c) => Datagram::Data(c.seal(packet, limits)?).encode(limits),
            #[cfg(feature = "legacy")]
            Cipher::Legacy(c) => c.seal(packet, limits),
        }
    }
    pub fn open(
        &mut self,
        epoch: SessionEpoch,
        bytes: Bytes,
        limits: ProtocolLimits,
    ) -> Result<DecodedPacket, ProtocolError> {
        self.check(epoch)?;
        if bytes.len() < 4 {
            return Err(ProtocolError::Incomplete);
        }
        if bytes[3] > 1 {
            return Err(ProtocolError::InvalidField("cipher slot"));
        }
        let slot = self.slots[bytes[3] as usize]
            .as_mut()
            .ok_or(ProtocolError::UnexpectedMessage)?;
        let (packet, integrity) = match &mut slot.cipher {
            Cipher::Aes(c) => {
                let Datagram::Data(data) = Datagram::decode(bytes, limits)? else {
                    return Err(ProtocolError::UnexpectedMessage);
                };
                (c.open(&data, limits)?, Integrity::Authenticated)
            }
            #[cfg(feature = "legacy")]
            Cipher::Legacy(c) => (
                c.open(&bytes, limits)?,
                if self.version == WireVersion::V1 {
                    Integrity::NoIntegrity
                } else {
                    Integrity::UnkeyedChecksum
                },
            ),
        };
        Ok(DecodedPacket { packet, integrity })
    }
    pub fn kind(&self, slot: u8) -> Option<CipherKind> {
        self.slots
            .get(slot as usize)
            .and_then(Option::as_ref)
            .map(|s| s.material.kind())
    }
    pub fn needs_rotation(&self) -> bool {
        self.primary
            .and_then(|i| self.slots[i as usize].as_ref())
            .is_some_and(|s| match &s.cipher {
                Cipher::Aes(c) => c.needs_rotation(),
                #[cfg(feature = "legacy")]
                Cipher::Legacy(c) => c.needs_rotation(),
            })
    }
    pub fn close(&mut self) {
        self.slots = [None, None];
        self.primary = None;
        self.local_pending = None;
        self.remote_pending = None;
        self.closed = true;
    }
    /// Drops all keys/windows and invalidates old local callbacks, even if RNG then fails.
    pub fn reconnect(&mut self) -> Result<SessionEpoch, ProtocolError> {
        self.close();
        self.epoch = SessionEpoch::generate()?;
        self.generations = [0; 2];
        self.closed = false;
        Ok(self.epoch)
    }
}
