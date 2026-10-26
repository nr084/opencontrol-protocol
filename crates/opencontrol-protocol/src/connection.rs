//! Session lifetime coordinator, with local epoch-fenced callbacks. No transport ownership.
use crate::{
    datagram::NetworkPacket,
    liveness::{CloseReason, Liveness, TimerEvents, TimerProfile},
    s2s::{EndpointMachine, EndpointRole, EndpointState, Flow, IpConfig2},
    session::{AckOutcome, DecodedPacket, KeySlots, SessionEpoch},
    state::ControlEvent,
    *,
};
use bytes::Bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProfile {
    ClientServer(Role),
    SiteToSite(EndpointRole),
}
#[derive(Debug, Clone)]
enum Machine {
    Client(StateMachine),
    Endpoint(EndpointMachine),
}
impl Machine {
    fn new(profile: SessionProfile) -> Self {
        match profile {
            SessionProfile::ClientServer(role) => Self::Client(StateMachine::new(role)),
            SessionProfile::SiteToSite(role) => Self::Endpoint(EndpointMachine::new(role)),
        }
    }
    fn observe(&mut self, flow: Flow, m: &ControlMessage) -> Result<ControlEvent, ProtocolError> {
        match self {
            Self::Client(c) => {
                if flow == Flow::Incoming {
                    c.incoming_event(m)
                } else {
                    c.outgoing(m)?;
                    Ok(ControlEvent::Accepted)
                }
            }
            Self::Endpoint(e) => {
                e.observe(flow, m)?;
                Ok(if e.state() == EndpointState::Closed {
                    ControlEvent::PeerRejected
                } else {
                    ControlEvent::Accepted
                })
            }
        }
    }
    fn active(&self) -> bool {
        match self {
            Self::Client(c) => c.state() == ProtocolState::Active,
            Self::Endpoint(e) => e.state() == EndpointState::Active,
        }
    }
    fn closed(&self) -> bool {
        match self {
            Self::Client(c) => c.state() == ProtocolState::Closed,
            Self::Endpoint(e) => e.state() == EndpointState::Closed,
        }
    }
    fn close(&mut self) {
        match self {
            Self::Client(c) => c.close(),
            Self::Endpoint(e) => e.close(),
        }
    }
    fn version(&self) -> Option<WireVersion> {
        match self {
            Self::Client(c) => c.version(),
            Self::Endpoint(e) => e.version(),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub address: [u8; 4],
    pub port: u16,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    Accepted,
    Ignored {
        opcode: u8,
    },
    ReplyInvalidRequest,
    PeerRejected,
    Routes {
        changed: bool,
        complete: bool,
        safe_lan_changed: bool,
    },
    KeyInstalled {
        slot: u8,
        ack_required: bool,
    },
    KeyAcknowledged(AckOutcome),
}
#[derive(Debug)]
pub struct ProtocolSession {
    profile: SessionProfile,
    limits: ProtocolLimits,
    machine: Machine,
    keys: KeySlots,
    routes: RouteState,
    binding: Option<BindingSecret>,
    peer: Option<PeerEndpoint>,
    timers: Liveness,
    initial_cep: u16,
    key_ack_deadline: Option<u64>,
}
impl ProtocolSession {
    pub fn new(
        profile: SessionProfile,
        offered_version: WireVersion,
        limits: ProtocolLimits,
        legacy: LegacyPolicy,
        now_ms: u64,
        cep: u16,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            profile,
            limits,
            machine: Machine::new(profile),
            keys: KeySlots::new(offered_version, legacy)?,
            routes: tracker(profile, limits),
            binding: None,
            peer: None,
            timers: Liveness::new(timer_profile(profile), now_ms, cep)?,
            initial_cep: cep,
            key_ack_deadline: None,
        })
    }
    pub fn epoch(&self) -> SessionEpoch {
        self.keys.epoch()
    }
    pub fn version(&self) -> Option<WireVersion> {
        self.machine.version()
    }
    pub fn active(&self) -> bool {
        self.machine.active()
    }
    pub fn keys(&self) -> &KeySlots {
        &self.keys
    }
    pub fn routes(&self) -> &RouteState {
        &self.routes
    }
    pub fn peer(&self) -> Option<PeerEndpoint> {
        self.peer
    }
    fn check(&self, epoch: SessionEpoch) -> Result<(), ProtocolError> {
        if epoch != self.epoch() {
            return Err(ProtocolError::StaleSession);
        }
        if self.machine.closed() {
            return Err(ProtocolError::Closed);
        }
        Ok(())
    }
    /// Outgoing messages are observed only after a successful send. Incoming S2S proposals
    /// are installed before emitting KeyInstalled{ack_required:true}; send R9 then observe it.
    pub fn observe(
        &mut self,
        epoch: SessionEpoch,
        flow: Flow,
        message: &ControlMessage,
        now: u64,
    ) -> Result<SessionEvent, ProtocolError> {
        self.check(epoch)?;
        if let Some(reason) = self.poll(epoch, now)?.close {
            self.close(now, reason)?;
            return Err(ProtocolError::Closed);
        }
        let mut candidate = self.machine.clone();
        let disposition = match candidate.observe(flow, message) {
            Err(ProtocolError::RekeyCollision) => {
                self.close(now, CloseReason::ProtocolViolation)?;
                return Err(ProtocolError::RekeyCollision);
            }
            other => other?,
        };
        if candidate.closed() {
            self.close(now, CloseReason::ProtocolViolation)?;
            return Ok(SessionEvent::PeerRejected);
        }
        if self.machine.version().is_none() {
            if let Some(v) = candidate.version() {
                self.keys.set_version(v)?;
            }
        }
        let cep = match message {
            ControlMessage::IpConfig(c) => Some(c.cep),
            ControlMessage::S2sConfig3(c) => Some(c.cep),
            _ => None,
        };
        if cep.is_some_and(|c| c < 2) {
            return Err(ProtocolError::InvalidField("CEP"));
        }
        let was_active = self.machine.active();
        let mut event = match disposition {
            ControlEvent::Ignored { opcode } => SessionEvent::Ignored { opcode },
            ControlEvent::ReplyInvalidRequest => SessionEvent::ReplyInvalidRequest,
            _ => SessionEvent::Accepted,
        };
        let mut next_routes = None;
        if let ControlMessage::Routes(routes) = message {
            if flow == Flow::Incoming {
                let mut next = self.routes.clone();
                let old = self.routes.current().map(RouteConfiguration::safe_lan);
                let changed = matches!(next.apply(routes)?, RouteUpdate::Changed(_));
                event = SessionEvent::Routes {
                    changed,
                    complete: !next.maintenance_pending(),
                    safe_lan_changed: old != next.current().map(RouteConfiguration::safe_lan),
                };
                next_routes = Some(next);
            }
        }
        if disposition == ControlEvent::Accepted {
            let initial = match message {
                ControlMessage::InitialConfig(c) => Some(AnyCipherConfig::Aes(CipherConfig {
                    slot: c.cipher.slot,
                    key: crypto::SessionKey::from_bytes(*c.cipher.key.as_bytes()),
                })),
                ControlMessage::LegacyInitialConfig(c) => {
                    Some(AnyCipherConfig::Legacy(LegacyCipherConfig {
                        slot: c.cipher.slot,
                        key: LegacyKey::from_bytes(
                            *c.cipher.key.key_bytes(),
                            *c.cipher.key.salt_bytes(),
                        ),
                    }))
                }
                ControlMessage::S2sConfig2(IpConfig2::Accepted { cipher, .. }) => {
                    Some(cipher.duplicate_secret())
                }
                _ => None,
            };
            if let Some(config) = initial {
                self.keys.install_initial(epoch, &config)?;
            }
            let proposal = match message {
                ControlMessage::KeyChange(c) => Some(AnyCipherConfig::Aes(CipherConfig {
                    slot: c.slot,
                    key: crypto::SessionKey::from_bytes(*c.key.as_bytes()),
                })),
                ControlMessage::LegacyKeyChange(c) => {
                    Some(AnyCipherConfig::Legacy(LegacyCipherConfig {
                        slot: c.slot,
                        key: LegacyKey::from_bytes(*c.key.key_bytes(), *c.key.salt_bytes()),
                    }))
                }
                _ => None,
            };
            if let Some(config) = proposal {
                if flow == Flow::Outgoing {
                    self.keys.propose(epoch, &config)?;
                    self.key_ack_deadline = Some(now.saturating_add(20_000));
                } else {
                    self.keys.receive_proposal(epoch, &config)?
                }
                event = SessionEvent::KeyInstalled {
                    slot: config.slot(),
                    ack_required: flow == Flow::Incoming,
                };
            }
            if matches!(message, ControlMessage::KeyChanged(_)) {
                event = SessionEvent::KeyAcknowledged(if flow == Flow::Incoming {
                    let outcome = self.keys.acknowledge_local(epoch)?;
                    if matches!(outcome, AckOutcome::Promoted { .. }) {
                        self.key_ack_deadline = None;
                    }
                    outcome
                } else {
                    self.keys.acknowledge_peer(epoch)?
                });
            }
            match message {
                ControlMessage::IpConfig(c) => self.binding = Some(c.secret.clone()),
                ControlMessage::S2sConfig3(c) => self.binding = Some(c.secret.clone()),
                _ => (),
            }
        }
        self.machine = candidate;
        if let Some(routes) = next_routes {
            self.routes = routes;
        }
        if let Some(cep) = cep {
            self.timers.set_cep(cep)?;
        }
        if !was_active && self.machine.active() {
            self.timers.activate(now)?;
        }
        let refresh = match self.profile {
            SessionProfile::ClientServer(Role::Client) => {
                matches!(message.opcode(), 9 | 11 | 13 | 14 | 19)
            }
            SessionProfile::ClientServer(Role::Server) => matches!(message.opcode(), 8 | 10 | 12),
            SessionProfile::SiteToSite(_) => matches!(message.opcode(), 8 | 10),
        };
        if flow == Flow::Incoming
            && disposition == ControlEvent::Accepted
            && (!was_active || refresh)
        {
            self.timers.control_received(now)?;
        }
        if flow == Flow::Outgoing && matches!(message, ControlMessage::KeepaliveRequest) {
            self.timers.control_sent(now)?;
        }
        if flow == Flow::Outgoing
            && matches!(
                message,
                ControlMessage::KeyChange(_) | ControlMessage::LegacyKeyChange(_)
            )
        {
            self.timers.rekey_sent(now)?;
        }
        Ok(event)
    }
    /// Binding is explicit and does not authorize source-port migration in the same session.
    pub fn bind_endpoint(
        &mut self,
        epoch: SessionEpoch,
        endpoint: PeerEndpoint,
        secret: &BindingSecret,
    ) -> Result<(), ProtocolError> {
        self.check(epoch)?;
        use subtle::ConstantTimeEq;
        if endpoint.port == 0 {
            return Err(ProtocolError::InvalidField("endpoint port"));
        }
        if self.peer.is_some_and(|old| old != endpoint) {
            return Err(ProtocolError::InvalidField(
                "endpoint migration requires new session",
            ));
        }
        let expected = self
            .binding
            .as_ref()
            .ok_or(ProtocolError::UnexpectedMessage)?;
        if !bool::from(expected.0.ct_eq(&secret.0)) {
            return Err(ProtocolError::InvalidField("binding secret"));
        }
        self.peer = Some(endpoint);
        Ok(())
    }
    pub fn open_from(
        &mut self,
        epoch: SessionEpoch,
        peer: PeerEndpoint,
        bytes: Bytes,
        now: u64,
    ) -> Result<DecodedPacket, ProtocolError> {
        self.check(epoch)?;
        if self.peer != Some(peer) {
            return Err(ProtocolError::InvalidField("unbound endpoint"));
        }
        // Validate time before decrypting so an invalid timestamp cannot consume replay state.
        self.poll(epoch, now)?;
        if self.machine.closed() {
            return Err(ProtocolError::Closed);
        }
        let packet = self.keys.open(epoch, bytes, self.limits)?;
        self.timers.udp_received(now)?;
        Ok(packet)
    }
    pub fn seal(
        &mut self,
        epoch: SessionEpoch,
        packet: &NetworkPacket,
        now: u64,
    ) -> Result<Bytes, ProtocolError> {
        self.check(epoch)?;
        if !self.active() || self.peer.is_none() {
            return Err(ProtocolError::UnexpectedMessage);
        }
        self.poll(epoch, now)?;
        if self.machine.closed() {
            return Err(ProtocolError::Closed);
        }
        let b = self.keys.seal(epoch, packet, self.limits)?;
        self.timers.udp_sent(now)?;
        Ok(b)
    }
    pub fn poll(&mut self, epoch: SessionEpoch, now: u64) -> Result<TimerEvents, ProtocolError> {
        if epoch != self.epoch() {
            return Err(ProtocolError::StaleSession);
        }
        let events = self.timers.poll(now)?;
        if self
            .key_ack_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            self.close(now, CloseReason::RekeyTimeout)?;
            return self.timers.poll(now);
        }
        if let Some(reason) = events.close {
            self.close(now, reason)?;
        }
        Ok(events)
    }
    pub fn close(&mut self, now: u64, reason: CloseReason) -> Result<(), ProtocolError> {
        self.timers.close(now, reason)?;
        self.machine.close();
        self.keys.close();
        self.binding = None;
        self.key_ack_deadline = None;
        self.peer = None;
        self.routes = tracker(self.profile, self.limits);
        Ok(())
    }
    pub fn close_deadline(&self) -> Option<u64> {
        self.timers.transport_close_deadline()
    }
    /// Old OS resources remain owned by the old epoch in RouteApplications until acknowledged
    /// cleanup. They must not be silently forgotten when this logical session resets.
    pub fn reconnect(&mut self, now: u64) -> Result<SessionEpoch, ProtocolError> {
        self.close(now, CloseReason::PeerClosed)?;
        let epoch = self.keys.reconnect()?;
        self.machine = Machine::new(self.profile);
        self.routes = tracker(self.profile, self.limits);
        self.timers = Liveness::new(timer_profile(self.profile), now, self.initial_cep)?;
        Ok(epoch)
    }
}
fn timer_profile(profile: SessionProfile) -> TimerProfile {
    match profile {
        SessionProfile::ClientServer(Role::Client) => TimerProfile::Client,
        SessionProfile::ClientServer(Role::Server) => TimerProfile::Server,
        SessionProfile::SiteToSite(_) => TimerProfile::SiteToSite,
    }
}
fn tracker(profile: SessionProfile, limits: ProtocolLimits) -> RouteState {
    match profile {
        SessionProfile::ClientServer(_) => RouteState::new(limits),
        SessionProfile::SiteToSite(_) => RouteState::for_endpoint(limits),
    }
}
