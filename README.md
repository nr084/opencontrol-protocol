# OpenControl Protocol Library

`opencontrol-protocol` 0.1.0 is an independent, synchronous Rust library for the
observed protocol. It owns no sockets and requires no async runtime. The server
supplies decrypted TLS bytes, authentication decisions, configuration and UDP I/O.
Wire versions 1–4 are distinct from the crate version.

```rust
use opencontrol_protocol::*;

let limits = ProtocolLimits::default();
let mut decoder = ProtocolDecoder::new(limits);
let incoming = [0x4b, 5, 0, 22, 4]; // already decrypted application bytes
let mut remaining = incoming.as_slice();
while !remaining.is_empty() {
    let consumed = decoder.push_bytes(remaining)?;
    remaining = &remaining[consumed..];
    if let Some(frame) = decoder.next_frame()? {
        let message = ControlMessage::decode(frame, WireVersion::V4, limits)?;
        // Pass message to the application and ordering validator.
        assert!(matches!(message, ControlMessage::Version(WireVersion::V4)));
    }
}
decoder.finish()?; // call at EOF, not between reads

let response = ControlMessage::Ok(vec![]);
let outgoing = ProtocolEncoder::new(limits).encode(&response, WireVersion::V4)?;
assert_eq!(outgoing.as_ref(), &[0x4b, 5, 0, 3, 0]);
# Ok::<(), ProtocolError>(())
```

Add the library to a server with a path dependency:

```toml
[dependencies]
opencontrol-protocol = { path = "../library/crates/opencontrol-protocol" }
```

`push_bytes` consumes at most one frame. Always drain `next_frame` before feeding
the remainder; this keeps memory bounded for coalesced input. Negotiation happens
through `StateMachine`; use its `version()` for subsequent message decoding.
Observe both outgoing and incoming messages. Call `outgoing` after a successful
send. Match a CONNECT secret in the application before sending SecretReceived.

`DataCipher` owns one cipher slot. Keep two independent objects during rotation;
installation resets counters, promotion does not. Keys come from OS randomness.
`seal` generates fresh nonces; no deterministic production encryption API exists.
Use `Datagram::decode` and `DataCipher::open` before delivering inner packets.

See [PROTOCOL.md](PROTOCOL.md), [SECURITY.md](SECURITY.md) and
[PROJECT_STATE.md](PROJECT_STATE.md) for evidence, limitations and readiness.
No OpenControl Server interoperability claim is made by this release.

