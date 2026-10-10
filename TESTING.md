# Testing

From `library`, with a stable Rust toolchain:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --doc
```

Integration tests cover committed synthetic golden vectors, negative framing
fixtures, every stream split point/coalescing, all four wire versions, credential
and TLV errors, resource limits, state ordering, late rekey promotion, replay edges,
bad GCM tags, wrong keys/slots and Debug redaction. Property tests exercise arbitrary
parser inputs and unknown frame roundtrips. Synthetic vectors are explicitly not
reference-client captures; their AES primitive was independently cross-checked
by the prior research with two implementations.

`cargo run -p opencontrol-protocol --example oc-dissect -- stream.bin 4` prints
opcode/length/state using library codecs. It never prints payloads. Input must be
an extracted decrypted client-to-server stream; a one-direction trace cannot
prove complete handshake ordering. PCAP/TLS decryption is outside this tool.

Fuzzing requires cargo-fuzz, a nightly compiler and a supported sanitizer platform
(use Linux for the campaign):

```sh
cargo fuzz run fuzz_control_decoder -- -max_total_time=60
cargo fuzz run fuzz_datagram_decoder -- -max_total_time=60
cargo fuzz run fuzz_state_machine -- -max_total_time=60
```

Targets are in a separate workspace and are not run by `cargo test --workspace`.
State target records are `direction:u8 (0=C→S, 1=S→C), opcode:u8,
payload_length:u16le, payload`. This developer envelope is not the wire format.
The committed `protocol/vectors/handshake_v4.bin` seed reaches Active and rekey;
its transcript is also checked in an integration test. Copy seeds into a disposable
fuzz corpus before a campaign; never mutate committed fixtures as a fuzz corpus.
The control/datagram targets assert lossless successful decode/re-encode. The state
target asserts invalid observations leave the state unchanged. Save any crash as
a sanitized regression fixture with provenance and a deterministic test.

Future acceptance requires connecting a native compatible client to an independent
server using this dependency, including login, binding, IPv4, keepalive, rotation,
loss/reordering and negative authentication. The historical lab tests validate
research facts; they do not test this Rust implementation against that peer.

