//! Caller-clock timers. No wall clock, sockets, sleeps or automatic I/O.
use crate::ProtocolError;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerProfile {
    Client,
    Server,
    SiteToSite,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Cancelled,
    ProtocolViolation,
    ControlTimeout,
    HandshakeTimeout,
    RekeyTimeout,
    PeerClosed,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TimerEvents {
    pub control_keepalive_due: bool,
    pub udp_keepalive_due: bool,
    pub rekey_due: bool,
    pub udp_stale: bool,
    pub close: Option<CloseReason>,
}
#[derive(Debug, Clone)]
pub struct Liveness {
    profile: TimerProfile,
    now: u64,
    started: u64,
    active: bool,
    control: u64,
    udp_rx: u64,
    control_tx: u64,
    udp_tx: u64,
    rekey: u64,
    cep_ms: u64,
    closed: Option<(CloseReason, u64)>,
}
impl Liveness {
    /// Time is caller-supplied monotonic milliseconds; CEP is seconds, not a key TTL.
    pub fn new(profile: TimerProfile, now: u64, cep: u16) -> Result<Self, ProtocolError> {
        if cep < 2 {
            return Err(ProtocolError::InvalidField("CEP"));
        }
        Ok(Self {
            profile,
            now,
            started: now,
            active: false,
            control: now,
            udp_rx: now,
            control_tx: now,
            udp_tx: now,
            rekey: now,
            cep_ms: u64::from(cep) * 1000,
            closed: None,
        })
    }
    fn time(&mut self, now: u64) -> Result<(), ProtocolError> {
        if now < self.now {
            return Err(ProtocolError::InvalidTime);
        }
        self.now = now;
        Ok(())
    }
    pub fn activate(&mut self, now: u64) -> Result<(), ProtocolError> {
        self.time(now)?;
        if self.closed.is_some() {
            return Err(ProtocolError::Closed);
        }
        self.active = true;
        self.control = now;
        self.udp_rx = now;
        self.control_tx = now;
        self.udp_tx = now;
        self.rekey = now;
        Ok(())
    }
    pub fn set_cep(&mut self, cep: u16) -> Result<(), ProtocolError> {
        if cep < 2 {
            return Err(ProtocolError::InvalidField("CEP"));
        }
        self.cep_ms = u64::from(cep) * 1000;
        Ok(())
    }
    pub fn control_received(&mut self, now: u64) -> Result<(), ProtocolError> {
        self.time(now)?;
        if self.closed.is_some() {
            return Err(ProtocolError::Closed);
        }
        self.control = now;
        Ok(())
    }
    /// Call only for application-approved bound-endpoint activity, not arbitrary UDP senders.
    pub fn udp_received(&mut self, now: u64) -> Result<(), ProtocolError> {
        self.time(now)?;
        if self.closed.is_some() {
            return Err(ProtocolError::Closed);
        }
        self.udp_rx = now;
        Ok(())
    }
    pub fn control_sent(&mut self, now: u64) -> Result<(), ProtocolError> {
        self.time(now)?;
        if self.closed.is_some() {
            return Err(ProtocolError::Closed);
        }
        self.control_tx = now;
        Ok(())
    }
    pub fn udp_sent(&mut self, now: u64) -> Result<(), ProtocolError> {
        self.time(now)?;
        if self.closed.is_some() {
            return Err(ProtocolError::Closed);
        }
        self.udp_tx = now;
        Ok(())
    }
    pub fn rekey_sent(&mut self, now: u64) -> Result<(), ProtocolError> {
        self.time(now)?;
        if self.closed.is_some() {
            return Err(ProtocolError::Closed);
        }
        self.rekey = now;
        Ok(())
    }
    pub fn close(&mut self, now: u64, reason: CloseReason) -> Result<(), ProtocolError> {
        self.time(now)?;
        if self.closed.is_none() {
            self.closed = Some((reason, now));
        }
        self.active = false;
        Ok(())
    }
    pub fn transport_close_deadline(&self) -> Option<u64> {
        self.closed.map(|(_, at)| at.saturating_add(5000))
    }
    pub fn poll(&mut self, now: u64) -> Result<TimerEvents, ProtocolError> {
        self.time(now)?;
        if let Some((reason, _)) = self.closed {
            return Ok(TimerEvents {
                close: Some(reason),
                ..Default::default()
            });
        }
        if (!self.active && now - self.started >= 10_000)
            || (self.active && now - self.control >= 120_000)
        {
            let reason = if self.active {
                CloseReason::ControlTimeout
            } else {
                CloseReason::HandshakeTimeout
            };
            self.close(now, reason)?;
            return Ok(TimerEvents {
                close: Some(reason),
                ..Default::default()
            });
        }
        if !self.active {
            return Ok(TimerEvents::default());
        }
        Ok(TimerEvents {
            control_keepalive_due: self.profile != TimerProfile::Server
                && now - self.control_tx >= 60_000,
            udp_keepalive_due: now - self.udp_tx >= 5000,
            rekey_due: now - self.rekey >= self.cep_ms / 2,
            udp_stale: now - self.udp_rx >= 33_000,
            close: None,
        })
    }
}
