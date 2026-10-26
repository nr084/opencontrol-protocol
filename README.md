<div align="center">

# OpenControl Protocol Library

**The protocol foundation for independent VPN clients and servers.**

Wire codecs, cryptography and session state in a reusable Rust library.

**English** · [Русский](README.ru.md)

[![Release](https://img.shields.io/github/v/release/nr084/opencontrol-protocol?label=release)](https://github.com/nr084/opencontrol-protocol/releases/latest)
[![Quality](https://github.com/nr084/opencontrol-protocol/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/nr084/opencontrol-protocol/actions/workflows/quality.yml)
[![Rust](https://img.shields.io/badge/Rust-stable-orange?logo=rust)](rust-toolchain.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

[Get started](#get-started) · [Capabilities](#capabilities) · [Documentation](#documentation) · [Release notes](CHANGELOG.md)

</div>

---

OpenControl Protocol Library implements the observed OpenControl wire protocol:
control messages, encrypted UDP packets, session transitions and route updates.
It provides a shared protocol layer for applications that supply their own transport
and operating-system integration.

**Current version:** `0.9.0` · **Crate:** `opencontrol-protocol` · **Wire versions:** `1–4`

## Capabilities

| Area | What the library provides |
|---|---|
| **Control channel** | Incremental framing, typed messages, bounded decoding and preservation of unknown payloads. |
| **Session lifecycle** | Client/server and S2S state machines, two key slots, reconnect fencing, caller-clock deadlines and cancellation. |
| **Data channel** | AES-128-GCM, UDP envelopes and replay windows scoped to each key slot and generation. |
| **Route updates** | Repeated, empty and multipart ROUTES; full-tunnel routes; separate safeLan status. |
| **Platform coordination** | Desired/applied route plans, operation acknowledgments, retry and resource ownership. |
| **Legacy compatibility** | Optional Blowfish counter-format support, enabled explicitly at build time and runtime. |

The core is synchronous and requires no async runtime. The application owns sockets,
TLS certificate verification, TUN/TAP, DNS, system routes and firewall policy.

## Get started

Add the released Git dependency to your application's `Cargo.toml`:

```toml
[dependencies]
opencontrol-protocol = { git = "https://github.com/nr084/opencontrol-protocol.git", tag = "v0.9.0", version = "=0.9.0" }
```

The library is distributed through GitHub and is not published to crates.io.
Commit your application's `Cargo.lock` for reproducible dependency resolution.
Development follows the latest stable Rust; the declared minimum is Rust 1.99.

### Handle repeated route updates

Keep one `RouteState` for the entire connection. A periodic message can be valid
without changing the effective configuration:

```rust
use opencontrol_protocol::{ProtocolError, ProtocolLimits, RouteState, RouteUpdate, Routes};

fn main() -> Result<(), ProtocolError> {
    let mut routes = RouteState::new(ProtocolLimits::default());
    let update = Routes { flags: 3, records: vec![] };

    assert!(matches!(routes.apply(&update)?, RouteUpdate::Changed(_)));
    assert!(matches!(routes.apply(&update)?, RouteUpdate::Unchanged(_)));
    Ok(())
}
```

`Unchanged` is a successful logical result: preserve the connection, keys and VPN
interface. It does not prove that earlier OS operations succeeded. Use
`RouteApplications` to acknowledge applied operations and retry failures, including
after an unchanged update. Multipart START/END updates defer OS application until END.

Run the executable example with a simulated platform:

```sh
cargo run --example client_routes
```

**Upgrading an existing client?** Replace any handler that treats another ROUTES
message as a terminal error. Updating the dependency alone cannot fix that handler.
See the [migration guide](MIGRATION.md), including the required Android integration.

## Integration choices

- **Coordinated sessions:** use `ProtocolSession` for state, keys, binding, routes
  and deadlines without transferring transport ownership to the library.
- **Individual primitives:** use the codecs, `RouteState`, `DataCipher` or `KeySlots`
  independently when your application already coordinates those responsibilities.
- **Site-to-Site:** select the separate certificate-based initiator or acceptor
  profile. The transport authenticates certificates and selects the role.
- **Legacy:** enable Cargo feature `legacy` and runtime
  `LegacyPolicy::ExplicitlyEnabled`. There is no automatic downgrade.

See [architecture](ARCHITECTURE.md), [S2S](S2S.md) and [legacy compatibility](LEGACY.md).

## Verification and compatibility

Version 0.9.0 passed **50 automated tests including doctests**, stable Rust quality
checks and four Linux nightly sanitizer fuzz smoke targets. A real **21-minute
client session** survived two periodic ROUTES updates and one rekey without
reconnecting. Both S2S roles and explicit legacy operation were also exercised.
Exact results and scope are recorded in the [validation report](VALIDATION.md).

The API is pre-1.0. Crate, product, wire and TLS versions are separate concepts.
Legacy checksums are not cryptographic authentication. safeLan is a status value,
not an instruction to block LAN access. IPv6 packet envelopes can be represented;
IPv6 address/route negotiation and end-to-end interoperability are not established.
No universal product compatibility, seamless NAT migration or indefinite key overlap
is claimed. See [security properties](SECURITY.md).

## Documentation

| Guide | Contents |
|---|---|
| [Migration](MIGRATION.md) | Breaking changes, consumer updates and Android requirements. |
| [Route and DNS integration](ROUTES_INTEGRATION.md) | Endpoint protection, acknowledged application, ownership and recovery. |
| [Site-to-Site](S2S.md) | Certificate-selected roles, handshake and key transitions. |
| [Legacy compatibility](LEGACY.md) | Opt-in policy, wire format and integrity limits. |
| [Protocol specification](PROTOCOL.md) | Message layouts, semantics and evidence. |
| [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) | Module boundaries and security contracts. |
| [Testing](TESTING.md) · [Validation](VALIDATION.md) | Reproducible checks and measured results. |
| [Changelog](CHANGELOG.md) | Release history and API changes. |

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
cargo doc --workspace --no-deps --all-features --locked
```

CI also checks default features and runs Linux nightly fuzz smoke. Protocol changes
need evidence and a synthetic or sanitized regression test. Never include credentials,
session keys or private captures in issues, fixtures or fuzz corpora.

---

[MIT license](LICENSE) · [Report an issue](https://github.com/nr084/opencontrol-protocol/issues) · [Русская документация](README.ru.md)
