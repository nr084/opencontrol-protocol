# Architecture

One synchronous crate, no async runtime or transport/OS ownership:

1. `ProtocolDecoder`/`ProtocolEncoder`: bounded incremental framing.
2. `ControlMessage`: exact version-dependent payloads, bounded unknown bytes.
3. `StateMachine` and `s2s::EndpointMachine`: distinct role/state receive policies.
4. `crypto`, `datagram`, optional `legacy`: exact packet crypto and replay.
5. `session::KeySlots`: two slots/generations, pending ACK and local epoch fencing.
6. `RouteState`: atomic logical START/add-touch/END state, independent of keys.
7. `route_application::RouteApplications`: desired/applied plans and ownership.
8. `liveness::Liveness`: caller-clock events; `connection::ProtocolSession` coordinates
   state, keys, routes, peer binding, reconnect and local cancellation.

Adapters own sockets, TLS trust, authentication decisions, monotonic time, TUN,
route/DNS/firewall operations and durable recovery. No wire actions happen implicitly.
Observe outgoing messages only after a successful write; observe each incoming message
once. Decode/validate before observing. Poll deadlines even when reads stay silent.
Epoch tokens are local callback identities, not invented wire IDs.

ROUTES equality describes logical configuration. Desired state commits independently
of OS success; plans defer incomplete START/END maintenance, and actual per-operation
acknowledgment preserves partial success and failed-removal ownership. Cleanup of an
old epoch survives protocol reconnect. The platform serializes writes and reconciles
external changes; this in-memory journal cannot recover independently after SIGKILL.
See ROUTES_INTEGRATION.md for route and resolver recovery contracts.

Errors carry no secret input. Outer framing errors poison that decoder; active
unknown messages use an explicit state policy. Limits precede untrusted allocations:
control frame maximum63999, packet default8192, per-frame route count255 and aggregate
4096. Route owners are capped64, acknowledged resources16384. Core forbids unsafe.

Dependencies: bytes, thiserror, RustCrypto aes-gcm, getrandom, zeroize, subtle;
optional RustCrypto blowfish0.10 with zeroize, MIT OR Apache-2.0. No Tokio in core.
Public API is pre-1.0. MIGRATION.md records intentional safety differences from the
observed native implementation and changes from0.2.
