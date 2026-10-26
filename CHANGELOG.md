# Changelog

## 0.9.0 — 2026-10-26

- Added Q12/R13/R14 route queries and bounded zero-progress handling; typed wire
  refusals15/20/21 and certificate-selected S2S16/17/18 codecs and both endpoint roles.
- Added explicit ACTIVE receive dispositions for the C0019 sequence3/4/22/10/11.
  Authentication/setup rejection remains distinct.
- Preserved periodic empty ROUTES idempotence. Added4096-route aggregation across
 255-record batches, S2S ownership, START/END deferred OS plans, desired/applied
  acknowledgments, partial failure retry, conflict reannouncement and owned cleanup.
- Kept safeLan as status only. Full-tunnel plans protect the original endpoint uplink
  before /1 routes and retain endpoint protection through a split transition.
- Added optional feature/runtime-gated legacy Blowfish counter format for wire1–4,
  independent synthetic vectors and explicit weaker integrity labels; no downgrade.
- Accepted native same-slot peer replacement with a data-send barrier until R9,
  found and regression-tested during the live S2S acceptor check.
- Added two-slot/generation coordinator, epoch-fenced reconnect, separate control/UDP
  caller-clock timers, cancellation and bounded missing-ACK/transport-close policy.
- Added exact UTF-8 constructor and bounded NUL-terminated caller OS metadata;
  explicitly separated IPv6 envelope capability from unsupported address negotiation.
- Added migration, route/DNS integration, legacy/S2S docs, regression tests and fourth
  fuzz target. Core remains independent of sockets/TLS/OS and async runtime.

Breaking changes: new ControlMessage variants, ProtocolLimits.max_route_entries,
strict metadata termination, and rejection of overwriting a pending key proposal.
See [migration](MIGRATION.md). Clients must replace terminal ROUTES handlers; merely
updating this dependency cannot fix them. No Android/server products are changed.
See [validation](VALIDATION.md) for actual new-library checks and their limits.
GitHub release only; no crates.io publication.

## 0.2.0 — 2026-10-13

### Added

- `RouteState`, `RouteConfiguration` and `RouteUpdate` for repeated control ROUTES.
  Initial and changed effective configurations return `Changed`; periodic duplicates
  return `Unchanged`, including empty replacement lists.
- Atomic validation, bounded aggregation, deterministic set ordering and deduplication.
- Mark/touch/sweep replacement, additive batches, default-covering /1 routes and
  observed safeLan status. Unknown flag bits remain opaque metadata.
- Long-lived consumer example, regression vectors and Android migration instructions.
- Standalone live diagnostic and sanitized61-minute reference-server metadata:
  six periodic no-op ROUTES,725/725 echoes,121 rekeys, no reconnect.

### Clarified

- Existing E0024 helper calls establish bit0 maintenance start and bit1 completion.
  The previous shorthand about immediate clearing/bit1 disabling full routing was
  corrected. `Routes::replaces_routes` and `is_full_tunnel` remain wire-command helpers;
  consumers should use `RouteState` for current effective configuration.

### Consumer action required

- Replace terminal ROUTES handlers in active clients. A dependency version update
  alone cannot fix a client that returns a configuration error on every ROUTES.
- Apply the initial message and all subsequent messages to the same per-session
  tracker. Deliver actual changes to the platform; leave duplicate updates alone.

No changes to TLS, MFA, authentication, replay or rekey algorithms. No wire-format
change. Version0.2.0 is the pre-1.0 minor release for the new public feature API.

## 0.1.0

Initial protocol codecs, state validator, crypto/replay primitives, fixtures and fuzz targets.
