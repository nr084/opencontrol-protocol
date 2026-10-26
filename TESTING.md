# Testing 0.9.0

Use latest stable Rust (MSRV1.99), from the library root:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --locked
cargo run --example client_routes
```

Tests cover fragmentation/coalescing/EOF/limits; C0019 state-dependent handling;
wire1–4 AES/legacy configuration; S2S both roles and rejected short config; UTF-8,
NUL, normalization preservation and metadata byte boundaries; CEP1800 and repeated
empty ROUTES at600s before rekey; old periodic600/1200/pending-rekey regression;
256-record batches, safeLan/full tunnel, invalid atomic route messages; endpoint
protection, partial OS failure, failed removal ownership and conflict reannouncement;
AES golden/tag/replay/window edges, independent legacy vectors; two-slot replacement,
late/unsolicited ACK, collision, bounded ACK timeout, epoch-fenced reconnect and cancel.

`client_routes` uses virtual time and a mock platform. It does not sleep or change
an interface. `tools/routes-live` is a separate I/O adapter that calls this dependency;
it takes an explicit destination and trusted leaf certificate, credentials on stdin,
and duration1260..7200 seconds. Its `s2s` binary takes explicit certificate/key paths
and a selected AES/legacy profile. Never commit runtime keys or private transcripts.
No socket/TLS code is added to the core library.

Four fuzz targets live in a separate workspace. On Linux with nightly/cargo-fuzz:

```sh
cargo +nightly fuzz run fuzz_control_decoder -- -max_total_time=15
cargo +nightly fuzz run fuzz_datagram_decoder -- -max_total_time=15
cargo +nightly fuzz run fuzz_state_machine -- -max_total_time=15
cargo +nightly fuzz run fuzz_session -- -max_total_time=15
```

CI seeds control/state targets from committed synthetic fixtures. Session fuzz covers
role-specific state, caller epochs, route application failures and legacy packet
opening. A short smoke is not a sustained sanitizer campaign. Fuzz workspace build
checking on Windows is distinct from actual Linux sanitizer execution. Never mutate
committed fixtures as corpus. Reproduce crashes, fix and preserve sanitized regressions.
See VALIDATION.md for actually completed runs and historical evidence attribution.
