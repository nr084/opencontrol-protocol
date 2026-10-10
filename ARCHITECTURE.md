# Architecture

One crate avoids an unnecessary cross-crate secret API. Modules form these layers:

1. Caller-owned transport: TLS and datagram sockets, peer identity and certificate policy.
2. `ProtocolDecoder` / `ProtocolEncoder`: bounded, incremental outer framing.
3. `ControlMessage`: version-dependent typed payloads and lossless unknowns.
4. `crypto` / `datagram`: key ownership, authenticated packets and per-slot replay.
5. `StateMachine`: explicit handshake ordering and observed rekey promotion.

Dependencies are bytes, thiserror, RustCrypto aes-gcm, getrandom and zeroize.
There is no Tokio dependency, server configuration, user backend, route installation,
TUN/TAP, firewall manipulation or socket I/O. Core code forbids unsafe code.

The state validator is a server-focused protocol transcript model, not a scheduler.
It does not authenticate users, perform side effects, own keys or match UDP secrets.
It accepts repeated key changes and late acknowledgments as observed. Caller code
selects and maintains two DataCipher slots, deadlines and session cleanup.

Error handling uses `ProtocolError`; errors contain no sensitive input.
Outer framing errors poison the stream decoder. Unknown active server opcodes can
be observed without aborting, while unknown handshake messages fail ordering checks.
Known messages with malformed payloads fail typed decoding.

Limits are checked before untrusted allocations. The decoder accepts a single frame
per push, with a maximum of 63999 buffered bytes. Typed TLVs and routes have
collection and length limits. UDP parsing and encryption cap packet size at8192.

Strict parsing deliberately rejects nonmagic bytes instead of reproducing the
reference client's header scanning. Canonical emission is enforced for credential
NUL termination, OK list termination and Q_KEEPALIVE. Unknown reply payloads and
flag bits are preserved. These policy differences are recorded in PROTOCOL.md.

Public API is pre-1.0 and subject to deliberate revision. A future server must use
this library rather than copy or implement a second protocol parser.

