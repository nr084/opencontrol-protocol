# Changelog

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
