# Current phase

## 0.2.0 — 2026-10-13

Added per-session RouteState with atomic, bounded ROUTES application, exact-set
deduplication, mark/touch/sweep maintenance and Changed/Unchanged outcomes.
Resolved E0024 helper calls refine previous shorthand: bit0 marks prior entries,
bit1 prunes untouched entries; bit1 alone does not disable full tunneling.
Unknown bits remain opaque; bit2 is the observed status only. Wire codecs, state
transitions, authentication, TLS/MFA and rekey/crypto algorithms are unchanged.

Regression coverage includes two periodic virtual-time updates, empty/repeated
lists, clear, append, segmented snapshots, flag/status/full-tunnel changes, malformed
input, aggregate limits and preserved primary/pending slots plus both replay states.
The example tests acknowledged platform application and retry without tracker commit.
See VALIDATION.md for final results and ANDROID_MIGRATION.md for mandatory consumer
changes. The existing terminal Android ROUTES handler is not changed here.
Live acceptance completed after the user restarted the old reference-server VM:
3665.005 continuous seconds,6 real periodic ROUTES (flags3/count0), all Unchanged;
725/725 authenticated echoes,121 keepalive responses and121 rekey acknowledgments,
no disconnect/reconnect. A standalone Windows consumer uses the local0.2.0 library;
no TUN/OS routes or Android application were exercised. Evidence is in
protocol/fixtures/interop/routes-periodic-hour-20261013.json and VALIDATION.md.
The live pending-rekey race and changed route lists were not observed; automatic
tests cover those cases.32 automatic tests including docs pass after adding the
recorded-metadata regression. No credentials or lab configuration were changed.
Version 0.2.0 is released on GitHub as v0.2.0; no crates.io publication.

## Historical 0.1.0 checkpoint

Rust 0.1.0 library baseline implemented from existing protocol evidence.
Production interoperability acceptance is pending independent server/client testing.
Core toolchain follows latest stable; official channel checked on2026-10-10:
Rust1.99.0, release2026-10-01, compiler commitb940084d7 (2026-09-28).

# Proven

- Control magic/length/opcodes and incremental stream semantics: E0004/E0005.
- Version, credentials, OK TLVs, initial config and all four IP_CONFIG layouts.
- AES128/GCM key16/IV12/tag16, tag-before-ciphertext, no AAD: E0012/E0019.
- EtherType/sequence placement, two slots and64-entry replay: E0020/E0021/E0038.
- UDP CONNECT/keepalive canonical emission and observed handshake ordering.
- Existing research lab observations validate basic wire1..4 behavior, ordinary
  IPv4/rekey and bounded overlap/loss/replay experiments, not this new library.

# Implemented

- Standalone Cargo workspace and opencontrol-protocol0.1.0; no async or server I/O.
- Bounded incremental strict control decoder and exact encoder.
- Typed known messages, lossless unknowns, opaque ignored response payloads.
- Version-selected metadata/IP fields and typed routes; no network side effects.
- Explicit role-aware ordering validator and latest-pending-slot rekey behavior.
- Isolated AES-GCM and OS randomness, per-slot DataCipher and ReplayWindow.
- Sensitive Debug redaction, owned-key/secret and temporary plaintext zeroization.
- Synthetic committed fixtures/vectors, full handshake transcript and property tests.
- Three cargo-fuzz targets; developer oc-dissect example uses the same codecs.
- Canonical PROTOCOL.md, architecture/security/testing docs and standalone CI file.

# Tests

Final validation on Rust stable1.99.0:

- `cargo fmt --check`: pass (core and fuzz workspace).
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: pass.
- `cargo test --workspace --locked`:1 crypto unit test,14 integration/property tests,
  1 documentation example; all16 passed.
- 7 committed synthetic golden vectors,5 positive control fixtures and6 malformed
  framing fixtures checked. Committed handshake transcript reaches Active/rekey.
- `oc-dissect` smoke on version4 fixture: correct opcode22/length5/VersionReply.
- `cargo check --manifest-path fuzz/Cargo.toml --bins --locked`: all3 targets pass.

Fuzz targets pass cargo check on Windows. Native libFuzzer executables require
the supported campaign setup: the plain stable Windows build fails at linker entry
point selection; no sanitizer-enabled campaign is claimed. Linux nightly CI smoke
is configured but has not run in this local session.

# Unknown

- Secret generation/entropy/lifetime and complete wire error codes.
- Non-ASCII normalization, complete metadata acceptance and flags policy.
- Universal peer IPv6, NAT migration and long-term expiry behavior.
- Full legacy cipher kind0 semantics; not implemented.
- Broader client/platform interoperability beyond the measured Ubuntu/V4 server checkpoint.

# Next

Use this crate as the server's sole wire implementation. Perform an authorized
reference-client acceptance matrix, execute Linux nightly sanitizer fuzz campaigns,
and add sanitized captures/regressions. Keep application certificate policy,
authentication, secrets, endpoint matching, clocks, two-slot ownership and network
configuration in server code. Resolve unknowns through experiments before adding
wire semantics. API remains pre-1.0; production maturity is not claimed.

# Workspace hygiene

Temporary compilation artifacts were removed after validation: core target,
fuzz target and the alternate native build directory. Source files, both Cargo
lockfiles, fixtures and vectors remain. No research originals were changed.

# Downstream server checkpoint — 2026-10-10

OpenControl Server0.1.0 uses this crate as its sole wire implementation and has
measured unmodified-client acceptance on Ubuntu26.04.1:TLS1.3/wireV4, auth,
IP/routes/DNS, UDP/GCM/rekey/TUN, split/full LAN/NAT, static IP and negative auth.
Canonical API probes verify wire1..4 framing/data/tamper/replay independently.
The route-policy test brings the Linux suite to17 tests including docs;
fmt/Clippy -D warnings pass. Both dependency audits report zero vulnerabilities.

Canonical UDP Keepalive is also accepted server→client by the measured V4 client:
responding to an Active bound endpoint maintains the same idle session for90s;
without replies the client reconnects. Envelope codecs were already sufficient;
no new wire implementation or crypto semantics were added. Fixture metadata and
the server's PROJECT_STATE/evidence record this scoped result. No sanitizer or
sustained production-load certification is inferred from these tests.
