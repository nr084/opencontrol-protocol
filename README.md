# OpenControl Protocol Library

**English** · [Русский](README.ru.md)

[![Library quality](https://github.com/nr084/opencontrol-protocol/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/nr084/opencontrol-protocol/actions/workflows/quality.yml)

Independent Rust codecs and session primitives for the observed OpenControl Protocol.
**Crate: `opencontrol-protocol` · Library 0.9.0 · Wire 1–4 · MIT · latest stable Rust.**

```toml
[dependencies]
opencontrol-protocol = { git = "https://github.com/nr084/opencontrol-protocol.git", tag = "v0.9.0", version = "=0.9.0" }
```

GitHub distribution only; no crates.io publication. Commit your application's lockfile.
The crate version, product version, wire version and TLS ciphersuite are independent.

## Implemented

- Incremental bounded control framing, fragmentation/coalescing/EOF handling.
- Typed configuration, Q12/R13/R14 route queries, wire refusals and lossless unknowns.
- State-dependent client/server policy, including nonterminal ACTIVE 3/4/22/10/11.
- Persistent ROUTES tracking, empty/additive/segmented lists, status and unknown bits.
- Desired/applied route plans with ownership, acknowledgment, retry and endpoint protection.
- AES-128-GCM, exact UDP envelope, per-slot/per-generation replay windows.
- Explicit optional legacy Blowfish counter-format compatibility; no automatic downgrade.
- Separate certificate-selected S2S initiator/acceptor codecs and state transitions.
- Two-slot key coordinator, epoch-fenced reconnect, caller-clock liveness and cancellation.
- Exact UTF-8 credentials and safely terminated caller-supplied OS metadata.
- Synthetic vectors, property/regression tests, examples and four fuzz targets.

The core owns no sockets, TLS, async runtime, clocks, TUN/TAP, DNS or firewall.
Applications provide authenticated transport, platform configuration and durable cleanup.
`ProtocolSession` coordinates protocol state without performing I/O. Low-level codecs
and `RouteState` remain independently usable. See [architecture](ARCHITECTURE.md).

## Continuous ROUTES

ROUTES may arrive throughout an active session, including unchanged periodic messages.
Keep one tracker per session and process initial, repeated and empty messages.
`RouteUpdate::Unchanged` is success: preserve keys, replay state and the VPN interface.
`Changed` exposes the current complete effective configuration. Unknown bits stay opaque;
safeLan is status, not permission to enable LAN blocking or firewall rules.

Logical equality does not mean OS application succeeded. Use `RouteApplications` to
acknowledge individual operations and retry failures even on an unchanged update.
START batches defer OS application until END. Protect the endpoint through the original
uplink before full tunnel; cleanup removes only owned resources. Outgoing identical
advertisements must still be sent when requested. Run the executable mock example:

```sh
cargo run --example client_routes
```

This is a deterministic simulation, not a live-server test. Updating the dependency
alone cannot fix a client that still treats `ControlMessage::Routes` as terminal.
See [migration and Android requirements](MIGRATION.md) and [route/DNS contract](ROUTES_INTEGRATION.md).

## Compatibility boundaries

The API is pre-1.0; [0.9 breaking changes](MIGRATION.md) include enum variants, a new
aggregate limit, strict metadata termination and single-pending rekey policy.
Legacy requires Cargo `features=["legacy"]` **and** runtime explicit opt-in. Its
checksum is not a MAC. [Legacy details](LEGACY.md), [security](SECURITY.md).

[S2S](S2S.md) is a distinct certificate-selected profile, not IPsec. TLS certificate
trust and role selection belong to the transport. No complete subnet-conflict table,
seamless NAT migration, arbitrary product-version compatibility or unlimited key
lifetime is claimed. Generic IPv6 EtherType envelopes can be represented; IPv6
address/route negotiation and end-to-end interoperability are not established.
`Capabilities::require_ipv6_configuration()` returns an explicit unsupported error.

[Validation](VALIDATION.md) separates tests of this library from older probe/native
observations. It records actual checks and limits; OS updates and platform products
are not certified by a packet echo test.

## Documentation and development

- [Protocol/evidence](PROTOCOL.md), [implementation matrix](IMPLEMENTATION_MATRIX.md).
- [Migration](MIGRATION.md), [S2S](S2S.md), [route/DNS application](ROUTES_INTEGRATION.md).
- [Testing](TESTING.md), [changelog](CHANGELOG.md), [project state](PROJECT_STATE.md).

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
cargo doc --workspace --no-deps --all-features --locked
```

CI also tests default features and runs Linux nightly fuzz smoke. Short smoke is
not a sustained sanitizer campaign. `oc-dissect` prints opcode/length/state without
payloads; PCAP/TLS decryption is outside its scope. Contributions need evidence and
synthetic/sanitized regression fixtures. Never include credentials, session secrets
or private captures in issues, logs or fuzz corpora. [MIT license](LICENSE).
