//! Desired versus acknowledged OS resources. This module never changes the OS itself.
use crate::{
    routes::RouteProfile, session::SessionEpoch, ProtocolError, ProtocolLimits, Route,
    RouteConfiguration, RouteState, RouteUpdate, Routes,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointBypass {
    pub address: [u8; 4],
    pub gateway: Option<[u8; 4]>,
    pub uplink: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteVia {
    Tunnel,
    Uplink {
        gateway: Option<[u8; 4]>,
        interface: u64,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRoute {
    pub owner: SessionEpoch,
    pub route: Route,
    pub via: RouteVia,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOperation {
    Add(OwnedRoute),
    Remove(OwnedRoute),
}
#[derive(Debug, Clone)]
pub struct ApplicationPlan {
    id: u64,
    owner: SessionEpoch,
    operations: Vec<RouteOperation>,
    status: Option<bool>,
}
impl ApplicationPlan {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn owner(&self) -> SessionEpoch {
        self.owner
    }
    /// Ordered: preserve endpoint reachability before adding full-tunnel routes.
    pub fn operations(&self) -> &[RouteOperation] {
        &self.operations
    }
    pub fn safe_lan_status(&self) -> Option<bool> {
        self.status
    }
}
#[derive(Debug)]
struct Owner {
    tracker: RouteState,
    bypass: Option<EndpointBypass>,
    withdrawn: bool,
    status: Option<bool>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteNotice {
    pub logical_changed: bool,
    pub safe_lan_changed: bool,
    pub complete: bool,
    pub unknown_flags: u8,
}
#[derive(Debug)]
pub struct RouteApplications {
    limits: ProtocolLimits,
    owners: BTreeMap<SessionEpoch, Owner>,
    applied: BTreeMap<Route, Option<OwnedRoute>>,
    pending: Option<ApplicationPlan>,
    next_id: u64,
}
impl RouteApplications {
    pub fn new(limits: ProtocolLimits) -> Self {
        Self {
            limits,
            owners: BTreeMap::new(),
            applied: BTreeMap::new(),
            pending: None,
            next_id: 1,
        }
    }
    pub fn register(
        &mut self,
        owner: SessionEpoch,
        profile: RouteProfile,
        bypass: Option<EndpointBypass>,
    ) -> Result<(), ProtocolError> {
        if self.owners.contains_key(&owner) {
            return Err(ProtocolError::UnexpectedMessage);
        }
        if self.owners.len() >= 64 {
            return Err(ProtocolError::Limit("route owners"));
        }
        self.owners.insert(
            owner,
            Owner {
                tracker: if profile == RouteProfile::Endpoint {
                    RouteState::for_endpoint(self.limits)
                } else {
                    RouteState::new(self.limits)
                },
                bypass,
                withdrawn: false,
                status: None,
            },
        );
        Ok(())
    }
    /// Record an existing foreign resource from a trusted OS snapshot; it will never be removed.
    pub fn register_external(&mut self, route: Route) -> Result<(), ProtocolError> {
        if self.pending.is_some() {
            return Err(ProtocolError::UnexpectedMessage);
        }
        if self.applied.contains_key(&route) {
            return Err(ProtocolError::UnexpectedMessage);
        }
        if self.applied.len() >= 16384 {
            return Err(ProtocolError::Limit("applied routes"));
        }
        self.applied.insert(route, None);
        Ok(())
    }
    pub fn receive(
        &mut self,
        owner: SessionEpoch,
        message: &Routes,
    ) -> Result<RouteNotice, ProtocolError> {
        let state = self
            .owners
            .get_mut(&owner)
            .ok_or(ProtocolError::StaleSession)?;
        if state.withdrawn {
            return Err(ProtocolError::Closed);
        }
        let old_status = state.tracker.current().map(RouteConfiguration::safe_lan);
        let logical_changed = matches!(state.tracker.apply(message)?, RouteUpdate::Changed(_));
        Ok(RouteNotice {
            logical_changed,
            safe_lan_changed: old_status
                != state.tracker.current().map(RouteConfiguration::safe_lan),
            complete: !state.tracker.maintenance_pending(),
            unknown_flags: state.tracker.unknown_flags(),
        })
    }
    pub fn desired(&self, owner: SessionEpoch) -> Option<&RouteConfiguration> {
        self.owners.get(&owner).and_then(|o| o.tracker.current())
    }
    /// A network no-op may still need an OS retry or reclaiming a formerly conflicting route.
    pub fn begin_plan(
        &mut self,
        owner: SessionEpoch,
    ) -> Result<Option<ApplicationPlan>, ProtocolError> {
        if self.pending.is_some() {
            return Err(ProtocolError::UnexpectedMessage);
        }
        let state = self.owners.get(&owner).ok_or(ProtocolError::StaleSession)?;
        if !state.withdrawn && state.tracker.maintenance_pending() {
            return Ok(None);
        }
        let current = state.tracker.current();
        if current.is_none() && !state.withdrawn {
            return Ok(None);
        }
        let desired = if state.withdrawn {
            &[][..]
        } else {
            current.map(RouteConfiguration::routes).unwrap_or(&[])
        };
        let status = if state.withdrawn {
            None
        } else {
            current.map(RouteConfiguration::safe_lan)
        };
        let mut operations = Vec::new();
        let protection = state
            .bypass
            .filter(|endpoint| desired.iter().any(|r| contains(r, endpoint.address)));
        if !state.withdrawn
            && current.is_some_and(RouteConfiguration::is_full_tunnel)
            && state.bypass.is_none()
        {
            return Err(ProtocolError::UnsupportedCapability(
                "full tunnel requires original endpoint uplink",
            ));
        }
        if let Some(endpoint) = protection {
            let route = Route {
                network: endpoint.address,
                netmask: [255; 4],
            };
            if !self.applied.contains_key(&route) {
                operations.push(RouteOperation::Add(OwnedRoute {
                    owner,
                    route,
                    via: RouteVia::Uplink {
                        gateway: endpoint.gateway,
                        interface: endpoint.uplink,
                    },
                }));
            }
        }
        for route in desired {
            // Equal prefixes are first-owner-wins. Nested prefixes remain independent.
            if !self.applied.contains_key(route)
                && !operations
                    .iter()
                    .any(|op| matches!(op,RouteOperation::Add(r) if &r.route==route))
            {
                operations.push(RouteOperation::Add(OwnedRoute {
                    owner,
                    route: route.clone(),
                    via: RouteVia::Tunnel,
                }));
            }
        }
        for applied in self.applied.values().flatten().filter(|r| r.owner == owner) {
            if state.withdrawn
                || (applied.via == RouteVia::Tunnel && !desired.contains(&applied.route))
            {
                operations.push(RouteOperation::Remove(applied.clone()));
            }
        }
        if self.applied.len()
            + operations
                .iter()
                .filter(|op| matches!(op, RouteOperation::Add(_)))
                .count()
            > 16384
        {
            return Err(ProtocolError::Limit("applied routes"));
        }
        if operations.is_empty() && status == state.status {
            return Ok(None);
        }
        let plan = ApplicationPlan {
            id: self.next_id,
            owner,
            operations,
            status,
        };
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ProtocolError::Limit("application plans"))?;
        self.pending = Some(plan.clone());
        Ok(Some(plan))
    }
    /// One boolean per OS operation plus a separate status acknowledgment. Failed removals
    /// retain ownership; successful partial adds are remembered and can be rolled back/retried.
    /// Do not execute later operations after endpoint protection fails.
    pub fn acknowledge(
        &mut self,
        id: u64,
        succeeded: &[bool],
        status_applied: bool,
    ) -> Result<(), ProtocolError> {
        let plan = self.pending.as_ref().ok_or(ProtocolError::StaleSession)?;
        if plan.id != id || succeeded.len() != plan.operations.len() {
            return Err(ProtocolError::StaleSession);
        }
        let plan = self.pending.take().ok_or(ProtocolError::StaleSession)?;
        for (op, success) in plan.operations.iter().zip(succeeded) {
            if !success {
                continue;
            }
            match op {
                RouteOperation::Add(resource) => {
                    self.applied
                        .insert(resource.route.clone(), Some(resource.clone()));
                }
                RouteOperation::Remove(resource) => {
                    if self
                        .applied
                        .get(&resource.route)
                        .and_then(Option::as_ref)
                        .is_some_and(|r| r.owner == resource.owner)
                    {
                        self.applied.remove(&resource.route);
                    }
                }
            }
        }
        if status_applied {
            if let Some(owner) = self.owners.get_mut(&plan.owner) {
                owner.status = plan.status;
            }
        }
        Ok(())
    }
    pub fn applied(&self, owner: SessionEpoch) -> Vec<&OwnedRoute> {
        self.applied
            .values()
            .flatten()
            .filter(|r| r.owner == owner)
            .collect()
    }
    /// Does not drop ownership. Call begin_plan/acknowledge to finish cleanup, with retries.
    pub fn withdraw(&mut self, owner: SessionEpoch) -> Result<(), ProtocolError> {
        self.owners
            .get_mut(&owner)
            .ok_or(ProtocolError::StaleSession)?
            .withdrawn = true;
        Ok(())
    }
    pub fn forget(&mut self, owner: SessionEpoch) -> Result<(), ProtocolError> {
        if self.pending.as_ref().is_some_and(|p| p.owner == owner)
            || !self.applied(owner).is_empty()
        {
            return Err(ProtocolError::UnexpectedMessage);
        }
        let state = self.owners.get(&owner).ok_or(ProtocolError::StaleSession)?;
        if !state.withdrawn {
            return Err(ProtocolError::UnexpectedMessage);
        }
        self.owners.remove(&owner);
        Ok(())
    }
}
fn contains(route: &Route, address: [u8; 4]) -> bool {
    let mask = u32::from_be_bytes(route.netmask);
    u32::from_be_bytes(address) & mask == u32::from_be_bytes(route.network)
}
