//! Stateful, socket-independent application of repeated ROUTES messages.
//!
//! Bit0 starts mark/touch/sweep maintenance, bit1 finishes it, bits0+3 touch the
//! two default-covering /1 routes, and bit2 carries the observed safeLan status.
//! See PROTOCOL.md and protocol/research/routes-maintenance.md for evidence.
//! The caller retains interface addresses, connected routes, DNS and endpoint bypass.
//!
//! ```
//! use opencontrol_protocol::*;
//! let mut state = RouteState::new(ProtocolLimits::default());
//! let periodic = Routes { flags: 3, records: vec![] };
//! assert!(matches!(state.apply(&periodic)?, RouteUpdate::Changed(_)));
//! assert!(matches!(state.apply(&periodic)?, RouteUpdate::Unchanged(_)));
//! assert!(state.current().unwrap().routes().is_empty());
//! # Ok::<(), ProtocolError>(())
//! ```
use crate::{ProtocolError, ProtocolLimits, Route, Routes};

const DEFAULT_ROUTES: [Route; 2] = [
    Route {
        network: [0, 0, 0, 0],
        netmask: [128, 0, 0, 0],
    },
    Route {
        network: [128, 0, 0, 0],
        netmask: [128, 0, 0, 0],
    },
];
/// Hard local resource policy, not a negotiated protocol limit.
const MAX_STORED_ROUTES: usize = 4096;

/// Canonical set of server-requested routes and the confirmed client status.
/// This is not a complete OS interface configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConfiguration {
    routes: Vec<Route>,
    safe_lan: bool,
}
impl RouteConfiguration {
    /// Deduplicated, sorted IPv4 routes. Includes generated /1 default routes.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
    /// Observed status bit only; do not infer an OS security policy from its name.
    pub fn safe_lan(&self) -> bool {
        self.safe_lan
    }
    /// Full coverage through an explicit /0 or the observed default-covering /1 pair.
    pub fn is_full_tunnel(&self) -> bool {
        self.routes
            .iter()
            .any(|r| r.network == [0; 4] && r.netmask == [0; 4])
            || DEFAULT_ROUTES.iter().all(|r| self.routes.contains(r))
    }
}

/// A successful update always provides the current configuration.
#[derive(Debug, PartialEq, Eq)]
pub enum RouteUpdate<'a> {
    /// No platform update, reconnect, key reset or interface recreation is needed.
    Unchanged(&'a RouteConfiguration),
    /// Initial configuration or changed effective routes/status. Caller applies OS policy.
    Changed(&'a RouteConfiguration),
}

/// One tracker per session. All errors leave configuration and maintenance state unchanged.
/// Unknown flag bits are retained as metadata and have no invented policy or change event.
#[derive(Debug, Clone)]
pub struct RouteState {
    limits: ProtocolLimits,
    current: Option<RouteConfiguration>,
    touched: Vec<Route>,
    maintenance_pending: bool,
    last_flags: Option<u8>,
}
impl RouteState {
    pub fn new(limits: ProtocolLimits) -> Self {
        Self {
            limits,
            current: None,
            touched: Vec::new(),
            maintenance_pending: false,
            last_flags: None,
        }
    }
    pub fn current(&self) -> Option<&RouteConfiguration> {
        self.current.as_ref()
    }
    pub fn last_flags(&self) -> Option<u8> {
        self.last_flags
    }
    pub fn unknown_flags(&self) -> u8 {
        self.last_flags.unwrap_or(0) & !0x0f
    }
    pub fn maintenance_pending(&self) -> bool {
        self.maintenance_pending
    }

    /// Validate the entire message before applying it, even for directly constructed Routes.
    /// Route masks must be contiguous and networks aligned (local client planning policy).
    /// Per-message codec limits and a bounded aggregate set both apply.
    pub fn apply(&mut self, message: &Routes) -> Result<RouteUpdate<'_>, ProtocolError> {
        if message.records.len() > 255 || message.records.len() > self.limits.max_collection_items {
            return Err(ProtocolError::Limit("routes"));
        }
        self.limits.frame(6 + 8 * message.records.len())?;
        for route in &message.records {
            validate(route)?;
        }
        let capacity = self.limits.max_collection_items.min(MAX_STORED_ROUTES);
        let mut next = self.current.clone().unwrap_or(RouteConfiguration {
            routes: Vec::new(),
            safe_lan: false,
        });
        let mut touched = if message.replaces_routes() {
            Vec::new()
        } else {
            self.touched.clone()
        };
        let mut pending = self.maintenance_pending || message.replaces_routes();
        // Sweep on the candidate before adding this final batch so an atomic replacement
        // can succeed at the aggregate limit. Records in this batch are re-touched below.
        if message.finishes_routes() {
            next.routes.retain(|route| touched.contains(route));
        }
        for route in message
            .records
            .iter()
            .chain(DEFAULT_ROUTES.iter().filter(|_| message.is_full_tunnel()))
        {
            if !next.routes.contains(route) {
                if next.routes.len() >= capacity {
                    return Err(ProtocolError::Limit("stored routes"));
                }
                next.routes.push(route.clone());
            }
            if !touched.contains(route) {
                touched.push(route.clone());
            }
        }
        if message.finishes_routes() {
            pending = false;
        }
        next.routes.sort_unstable_by_key(|r| (r.network, r.netmask));
        next.safe_lan = message.safe_lan();
        let changed = self.current.as_ref() != Some(&next);
        // Commit only after every validation and allocation bound check succeeds.
        self.touched = touched;
        self.maintenance_pending = pending;
        self.last_flags = Some(message.flags);
        let current = self.current.insert(next);
        if changed {
            Ok(RouteUpdate::Changed(current))
        } else {
            Ok(RouteUpdate::Unchanged(current))
        }
    }
}
fn validate(route: &Route) -> Result<(), ProtocolError> {
    let mask = u32::from_be_bytes(route.netmask);
    let prefix = mask.leading_ones();
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if mask != expected {
        return Err(ProtocolError::InvalidField("route netmask"));
    }
    if u32::from_be_bytes(route.network) & !mask != 0 {
        return Err(ProtocolError::InvalidField("route network"));
    }
    Ok(())
}
