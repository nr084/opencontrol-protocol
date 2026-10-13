# Validation — OpenControl Protocol 0.2.0

Date: 2026-10-13. Local Rust stable1.99.0 on Windows. Following validation, the user
authorized GitHub publication as v0.2.0. No external registry publication is performed.
Both Cargo lockfiles select protocol library0.2.0; external Android dependencies
are unchanged and require their own migration.

## Automatic checks

| Check | Result |
|---|---|
|cargo fmt --check (workspace and fuzz)|Pass|
|cargo clippy --workspace --all-targets --locked -- -D warnings|Pass|
|cargo test --workspace --all-targets --locked|30 tests passed:1 crypto,14 existing protocol,2 route policy,11 route update/property/evidence,2 client example|
|cargo test --workspace --doc --locked|2 documentation examples passed|
|cargo check --manifest-path fuzz/Cargo.toml --bins --locked|All3 targets compile; RouteState error atomicity added to state target|
|cargo run --example client_routes|Virtual0/600/1200/1201s:Active, one initial platform update; changed full tunnel produces second update|
|git diff --check and local documentation links|Pass|

The existing lossless codec tests still pass, including arbitrary byte roundtrips.
No parsing, state-transition, key rotation, TLS, MFA or authentication algorithm was
weakened or changed. The new RouteState applies additional local planning validation
for contiguous masks and aligned networks before committing any state.

## Regression coverage

- Identical replacement messages; order changes and duplicate records.
- Initial empty list, repeated empty list and completed clearing of old entries.
- Additive updates and empty additive/completion batches retaining touched routes.
- Segmented mark/touch/sweep replacement with stale routes retained until completion.
- Empty full-tunnel updates, full→split changes and status-only bit2 changes.
- Opaque unknown flag bits without invented configuration changes.
- Invalid mask/network, count overflow, corrupt wire count and resource limits;
  no changes to effective state, last flags or pending maintenance on errors.
- Replacement at aggregate capacity and atomic failure on additive overflow.
- ROUTES during pending rekey:Active/version/primary/pending remain unchanged.
  Both actual DataCipher slots continue authenticated traffic and reject old ciphertext,
  demonstrating that replay state/counters were not reset. Later acknowledgment still
  promotes the expected pending slot under the unchanged state-machine algorithm.
- Platform failure and retry in the consumer example: old tracker retained until
  acknowledged application succeeds. The example does not implement real TUN operations.

## Live-server boundary

After the user restarted the old reference-server VM and provided authorized test
credentials, a standalone Windows diagnostic using the local0.2.0 library completed
an actual continuous **3665.005-second (61-minute5-second)** session against it.
The previously trusted leaf certificate and handshake signatures were verified.
No server configuration, TLS/authentication/MFA policy or Android source was changed.

| Observation | Result |
|---|---|
|Initial ROUTES|flags3/count0; Changed initializes the tracker|
|Periodic ROUTES|6 at599.611/1199.788/1799.470/2399.638/2999.800/3599.465s|
|Each repeat|flags3/count0, Unchanged, Active, primary slot1 preserved|
|Authenticated ICMP echoes to negotiated gateway|725 sent,725 valid replies|
|Control keepalive responses|121|
|Acknowledged ordinary rekeys|121; server accepted requested CEP60|
|Disconnects/reconnects during measured run|0|
|Completion|passed=true, exit0; socket closed by planned diagnostic completion|

The live run's clocks were not simulated. Six real repeats did not trigger a
configuration error, key reset or session termination; traffic continued after
each. Every observed repeat had no pending rekey acknowledgment; the pending-race
case remains covered by automatic tests, not asserted as a live observation.
There were no real route-list changes and no TUN/OS route application in this run.
This is library/consumer integration evidence, not Android end-to-end validation,
an unmodified native-client test or sustained production-load certification.

Sanitized observations and executable/source SHA256 provenance are stored in
[routes-periodic-hour-20261013.json](protocol/fixtures/interop/routes-periodic-hour-20261013.json).
The full local redacted JSONL is in the ignored protocol/live directory. No account
name, password, binding secret, key or raw credential/application payload is recorded.
The fixture contains parsed metadata, not raw control packets; its regression test
reconstructs only the observed empty ROUTES values. Synthetic routes_updates.json
remains labeled synthetic. No new sanitizer campaign ran; fuzz targets were compiled.

The initial local UDP adapter failed because desktop TCP metadata exposed IPv6
broker loopback. The diagnostic now binds UDP to a real IPv4 interface and uses
the requested endpoint. This is a test-transport fix, not a protocol/TLS change.
A five-minute pilot was deliberately stopped when the user requested a full hour;
it is not counted toward the continuous successful hour or recorded as a server drop.

## Required consumer change

The immediate disconnect described by the user is the active Android handler:
`ControlMessage::Routes(_) => return Err(EngineError::Configuration)`.
The existing library state machine already accepts ROUTES in Active. The new
version provides effective-state tracking; the terminal consumer handler must
still be replaced. See ANDROID_MIGRATION.md for initialization, candidate/commit,
Changed/Unchanged handling, platform acknowledgment and replacement-FD ownership.

The Android directory was read only and has not been modified by this task.
Existing unrelated local research/checkpoint edits were preserved. Temporary build
outputs created during validation are removed after final checks.
