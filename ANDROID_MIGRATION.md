# Android migration to OpenControl Protocol 0.2.0

Library changes alone do **not** fix the current Android disconnect. This task
does not modify client-android. Apply the following changes in that consumer.

The separate library diagnostic passed a real 61-minute session with six periodic
no-op updates and no reconnect. That result does not exercise this Android handler,
JNI updates or TUN ownership; the migration and Android acceptance below still apply.

## 1. Dependency and per-session ownership

Update its path/Git dependency or library submodule to published tag v0.2.0 and regenerate the
Android Rust Cargo.lock. For Git dependencies remove/update an old pinned `rev`;
do not assume a local workspace version updates a pinned remote dependency.
`opencontrol_protocol::VERSION` then reports0.2.0. No registry release is required.

Add `pub routes: RouteState` to `engine.rs::Session`, initialized with the same
`ProtocolLimits` as its codecs. Do not recreate it in pump or on periodic updates.
Retain negotiated `IpConfig` for later interface configuration; don't log its secret.

## 2. Initial ROUTES

In `transport.rs::connection`, replace direct use of the first raw `Routes` with:

```rust,ignore
let mut candidate = session.routes.clone();
let configuration = match candidate.apply(&routes)? {
    RouteUpdate::Changed(configuration) | RouteUpdate::Unchanged(configuration) => configuration,
};
let tunnel_config = tunnel_config_from_routes(&ip, configuration)?;
let fd = p.configure(&tunnel_config)?;
// Validate/register the transferred FD using the existing nonblocking/AsyncFd path.
session.routes = candidate; // Only after platform/FD setup succeeds.
```

Adapt the existing `engine.rs::tunnel_config` into a function accepting
`&RouteConfiguration`. Retain IP/netmask validation, the connected interface subnet,
DNS/domain handling and MTU. Iterate `configuration.routes()` for server routes;
generated /1 defaults are already present. Do not rebuild from only the latest
wire `Routes`, infer policy from count0 or append a /0 merely because a raw bit changed.
An explicit /0 wire record remains an explicit route. Preserve endpoint reachability
and protected TCP/UDP sockets in the platform layer.

## 3. Replace the terminal active handler

At `transport.rs::pump`, replace
`ControlMessage::Routes(_) => return Err(EngineError::Configuration)` with this flow:

```rust,ignore
ControlMessage::Routes(routes) => {
    let mut candidate = s.routes.clone();
    match candidate.apply(&routes)? {
        RouteUpdate::Unchanged(_) => {
            // No TUN recreation, reconnect, cancellation or key/counter reset.
        }
        RouteUpdate::Changed(configuration) => {
            let next = tunnel_config_from_routes(ip, configuration)?;
            // NEW platform contract; it does not exist in the current trait.
            let replacement_fd = p.update_routes(&next, configuration.safe_lan())?;
            if let Some(fd) = replacement_fd {
                let replacement = install_tun_fd(fd)?;
                tun = replacement; // pump must own a mutable AsyncFd, not borrow &AsyncFd.
            }
        }
    }
    s.routes = candidate; // Preserve pending mark/touch state even on Unchanged.
}
```

This is a migration sketch, not a drop-in patch: `tunnel_config_from_routes`,
`update_routes` and `install_tun_fd` must be implemented by the Android project.
Retain `ip` for pump; change its TUN argument to owned `mut tun: AsyncFd<File>`
if platform changes can transfer a replacement FD. Preserve the existing checked
FD ownership/nonblocking/registration logic in `install_tun_fd`.

Current `ControlIo::read` already calls `session.incoming`. Do not observe the same
message a second time in the match arm. `last_control` is already refreshed there;
retain that behavior for periodic updates. Do not alter rekey_pending, last_rotation,
machine slot selection, cipher objects, replay windows or authentication/TLS/MFA.

## 4. Platform contract and failure handling

Extend `Platform`/JNI with an acknowledged route-configuration update, for example:
`update_routes(&TunnelConfig, safe_lan: bool) -> Result<Option<i32>, EngineError>`.
`None` means no FD replacement; `Some(fd)` transfers a detached replacement FD.
For a status-only change, preserve routes and avoid rebuilding the interface.
The meaning of safeLan beyond the observed status is unknown: don't invent firewall
or MFA policy. Android may require a new VpnService interface for real route changes;
that is platform behavior, not a library instruction to reconnect the VPN session.

Platform code must validate/apply atomically or provide explicit rollback/recovery.
Keep the old TUN active until the new configuration and FD are ready. Never drop or
leak an owned transferred FD on failure. Commit the candidate tracker only after
successful OS/FD application. On failure retain the old tracker and retry/recover
according to explicit platform policy; do not silently claim application succeeded.
The library guarantees atomic protocol-state application, not an OS transaction.

Keep interface subnet, addresses, DNS/domain, MTU and endpoint protection independent
of the server-requested route set. A completed empty replacement removes server
routes, not necessarily the interface's connected subnet. Full tunnel can be an
empty wire message with bits0+3, producing two /1 routes. Preserve accumulated routes
when a message is additive. Do not discard bit2-only changes or guess unknown bits.

## 5. Required Android acceptance

- Initial routes followed by identical periodic updates at600 and1200 seconds:
  same session, no configure/update call for duplicates, no TUN recreation.
- Real additions, completed replacement/clear, full/split change and status-only
  change reach the platform with the full current route set.
- Repeat and malformed input while rekey acknowledgment is pending: no key-slot,
  replay-state or pending-ack reset caused by ROUTES handling.
- Platform failure/retry and replacement-FD ownership checks.
- Live authorized reference-server session longer than20 minutes with two periodic
  updates and continuous traffic. Automatic virtual-time tests are not this test.
