# OpenControl Protocol — canonical library specification

This specification describes the observed wire format, independent of product
names. Wire version is1..4; the Rust package version is0.1.0.

## Evidence and confidence

**KNOWN**: unambiguous static serializer/parser instructions in the inspected build.
**OBSERVED**: measured behavior in bounded laboratory experiments.
**INFERRED**: plausible interpretation, not established wire semantics.
**UNKNOWN**: no sufficient evidence; implementation must not invent behavior.

Evidence identifiers resolve in the separate project research area:
`../reverse/EVIDENCE.md` (E0001–E0059), `RUNTIME_EVIDENCE.md` (L groups),
`LAB_STRESS.md` (T groups), `VM_EVIDENCE.md` (V groups), `OS_METADATA.md`
(S groups), `SERVER_SETTINGS.md` (C groups). Research is not bundled into the
crate. No production credentials/captures are copied into library fixtures.

The older research uses CONFIRMED for KNOWN static facts. This library distinguishes
those from actual observations. Prior probe and native-client lab observations
support the basic wire1..4 handshake, ordinary IPv4 data and rotations. They do
not prove interoperability of this Rust library with a future server.

## Transport and outer framing

KNOWN: the control transport is a caller-established TLS byte stream. TLS record
boundaries carry no message semantics. The core sees decrypted bytes only.
UDP is a separate datagram transport. Socket addressing is outside this crate.
No scalar session identifier is established in either header. E0004–E0006/E0018.

| Header field | Offset | Size | Order | Allowed/meaning |
|---|---:|---:|---|---|
| Magic |0|1|byte|0x4b|
| Total length |1|2|little endian|includes four-byte header|
| Opcode |3|1|byte|known registry below; others UNKNOWN|
| Payload |4|total−4|message-specific|at least one byte|

KNOWN: nominal reference length validation5..64000; accumulator rejects64000
before completion. Library hard range5..63999, further restricted by caller
limits. No padding. Partial input is buffered; complete frames are drained one
at a time. Multiple frames per input are consumed using the returned byte count.
EOF with any unfinished bytes yields Incomplete. E0004/E0005.

Library policy: nonmagic input immediately fails and poisons the decoder. The
reference scans past nonmagic bytes while looking for a header. General recovery
after a bad length is UNKNOWN, so no speculative resynchronization is implemented.
Typed decode errors do not mutate the decoder or state machine.

## Control message definitions

All entries below inherit the four-byte control header, TLS transport, bounded
payload and typed-error/no-panic failure policy. Offsets below are payload-relative.
No additional per-message cryptography is performed inside TLS.
Optional fields are absent unless explicitly listed. State names describe ordering
in this library, not wire enum values. Known layouts are emitted exactly; unknown
bytes and flags are preserved. Character normalization is never invented.

### VERSION — opcode22

- Direction: C→S then S→C; states Initial then VersionReply.
- Payload: one byte negotiated version1..4; exact size1.
- Optional fields: none. Byte order: byte.
- KNOWN: reference offers4 and validates the server response against configured
  minimum..4. Library additionally refuses a response above the caller's offer.
- Failure: unsupported byte or extra payload rejected. UNKNOWN: future versions.
- Evidence: E0008. Fixture: version4.bin.

### USERNAME / PASSWORD — opcodes1 /2

- Direction: C→S; states Username / Password.
- Payload: opaque string bytes followed by a NUL; size1..max_string_size+1.
- Byte order: byte string; no optional fields.
- KNOWN: serializers emit stored username/password bytes, no challenge or KDF.
  Username expects OK; password expects OK or ERR. Backend decisions stay outside.
- Library policy: exactly one trailing NUL and no interior NUL.
- Failure: missing terminator, interior NUL or resource excess rejected.
- UNKNOWN: non-ASCII encoding/normalization and complete server credential grammar.
- Evidence: E0009/E0010/E0036. Synthetic credential fixtures only.

### OK — opcode3

- Direction: S→C; states UsernameResult / PasswordResult.
- Payload: repeated `kind:u8, length:u16be, value[length]`, terminated by kind0.
  Zero kind has no length/value. Minimal payload `00`.
- Optional fields: any number of nonzero-kind TLVs within limits; duplicate kinds
  and their order are preserved, not normalized. Unknown kinds remain opaque.
- KNOWN: password response parser consumes kind1 text for later browser handling.
- INFERRED: kind1 describes a verification URL; exact grammar/completion UNKNOWN.
  Library does not launch processes or perform verification flows.
- Failure: missing terminator, truncation, bytes after terminator or limit excess.
  Strict trailing-byte rejection is library policy.
- Evidence: E0011/E0041/E0054/E0055. Fixture: empty_ok.bin.

### ERR — opcode4

- Direction: S→C; handshake result/setup states.
- Payload: opaque nonempty bytes. Generic sender emits one byte. Some inspected
  waiters read the last byte; a complete error enum is UNKNOWN.
- No interpreted endian fields or optional structure. No invented wire error codes.
- KNOWN: ERR in password phase fails authentication; final e2 in binding waiter
  indicates duplicate connection. Local return values are not wire codes.
- Failure: outer framing/resource errors; state closes on modeled handshake ERR.
- Evidence: E0010/E0017/E0030; V0010 observed wrong-password ERR00.

### INITIAL_CONFIG — opcode5

- Direction C→S; state InitialConfig.
- Header/payload: `CEP:u16be, kind:u8=1, slot:u8=0..1` then version-selected body.
- V1/V2: AES config at offset4; exact payload23.
- V3/V4: version bytes[3] at4, build:u16be at7, OS code:u32be at9,
  fixed-size system description[128] at13, AES config at141; exact payload160.
- AES config: key_length:u8=16, IV_length:u8=12, tag_length:u8=16, key[16].
- Optional metadata exists only in V3/V4. Description bytes are preserved exactly.
- KNOWN: reference OS code2 identifies Linux;1 and3 are other observed platform
  codes. Library preserves any code without claiming acceptance by every peer.
  Reference emitted metadata is provenance, not an obligatory library identity.
- Crypto: new OS-random AES key, transported only through TLS; no KDF observed.
- Failure: wrong lengths, cipher kind, key/IV/tag dimensions or slot rejected.
- UNKNOWN: complete peer metadata acceptance policy.
- Evidence: E0012/E0013/E0035/E0059, S0001–S0003, C0001.

### IP_CONFIG — opcode6

- Direction S→C; state IpConfig; exact payload146(V1/V2),410(V3),411(V4).
- Address[4] at0, netmask[4] at4, CEP:u16be at8, DNS1[4] at10, DNS2[4] at14.
- V3/V4 optional extension: domain[256] at18, WINS1[4] at274, WINS2[4] at278.
- V4 only: flags:u8 at282. Secret[128] at18(V1/V2),282(V3),283(V4).
- Addresses are network-order bytes; domain fixed bytes preserve original padding.
- KNOWN: V4 bit0 selects a client DNS/adapter-order hook. Other bits UNKNOWN.
  Reference forces domain's last byte to NUL locally and rewrites loopback DNS/WINS
  locally. These transformations are not performed by the wire codec.
- Crypto: secret binds UDP endpoint; creation, entropy and lifetime UNKNOWN.
- Failure: any version/shape/length mismatch rejected; library assigns no IP or DNS.
- No wire gateway/MTU field established. Evidence: E0014/E0015/E0049.

### SECRET_RECEIVED — opcode7

- Direction S→C; state UdpBinding, transitions Active.
- Payload: opaque nonempty bytes, preserved; semantics/allowed values UNKNOWN.
- KNOWN: reference waiter verifies opcode only and stops CONNECT retransmission.
- Crypto: server must match CONNECT secret outside library before issuing this.
- Failure: framing/resource/state errors. Evidence: E0016/E0017.

### KEY_CHANGE — opcode8

- Direction C→S; state Active; replacement may occur with another change pending.
- Payload: kind1:u8, slot:u8 (0/1), AES config[19] as above. Exact length21.
- No optional fields. Crypto: fresh AES key under TLS; installation resets counters.
- KNOWN: slot is installed secondary; acknowledgment promotes current configuration.
- Failure: kind/slot/dimensions/length rejected. UNKNOWN: universal peer key lifetime.
- Evidence: E0025/E0037/E0038/E0050; lab ordinary rotation and overlap observations.

### KEY_CHANGED — opcode9

- Direction S→C; state Active, with or without pending rotation.
- Payload: opaque nonempty bytes, ignored by inspected promotion handler; constraints
  beyond framing UNKNOWN. No transaction ID established.
- KNOWN: acknowledgment promotes latest stored configuration, even if an earlier
  request caused the acknowledgment. Library clears latest pending slot on observation.
- OBSERVED: a late acknowledgment can cause transient loss in bounded lab tests.
- Failure: framing/resource/state errors. Evidence: E0025/E0050; T/V rekey tests.

### KEEPALIVE_REQUEST / KEEPALIVE_RESPONSE — opcodes10 /11

- Direction C→S / S→C; modeled state Active.
- Request payload: exact `00`. Response: opaque nonempty bytes, preserved.
- No optional request fields; response structure/allowed values UNKNOWN.
- KNOWN: reference also sends request during certificate waiting, outside the core
  post-TLS transcript. Control keepalive scheduling60s, active receive deadline120s.
- Caller owns time and scheduling. Failure: request nonzero/extra bytes, framing or
  invalid ordering. Evidence: E0023/E0037. Fixture: keepalive.bin.

### ROUTES — opcode19

- Direction S→C; state Active.
- Payload: flags:u8, count:u8, `count` records of network[4], netmask[4].
  Exact length2+8*count, count0..255 further constrained by caller limit.
- Network order address bytes. No gateway or optional trailing records.
- KNOWN: bit0 clears prior list, bit1 changes full routing, bits0+3 trigger two
  default-covering /1 routes locally; bit2 drives a status callback.
- UNKNOWN: complete peer policy meaning of bit2 and unobserved flag bits.
  Library preserves flags and installs no routes.
- Failure: count/length/resource mismatch. Evidence: E0024/E0056.

### Unknown control messages

Opcodes not above, including candidate12, are `Unknown(ControlFrame)`.
Payload bytes are preserved within framing limits. No direction/state/semantics
are invented. KNOWN: reference active incoming unknown opcode returns success;
unexpected handshake opcode fails. The library permits server-to-client Unknown
only in Active. Evidence: E0023/E0030. Opcode12 is not declared a disconnect.

## UDP envelopes

KNOWN: minimum dispatcher envelope5 bytes, magic0x4b, type at2. E0016/E0018/E0022.
Data and nondata layouts are distinct. No outer length field.

### CONNECT — type1

Direction C→S during UdpBinding. Canonical header `4b 00 01 00 00`, followed by
secret[128]; exact133 bytes. Fields are raw bytes, no optional fields. Secret equals
the server's IP_CONFIG secret. Reference retries after elapsed>2999ms. Client stops
on TLS opcode7. No encryption beyond previous TLS delivery of the secret.
Failure: wrong canonical size rejected. Noncanonical envelope bytes are preserved
as Unknown because receive-side meanings are not fully proven. Secret/endpoint
matching and expiration belong to caller. Evidence: E0016/E0017/E0044.

### UDP_KEEPALIVE — type2

Direction reference C→S, active idle transport. Exact five-byte `4b 00 02 00 00`.
No payload, sequence, tag or encryption. Library decodes canonical form only;
noncanonical envelopes remain Unknown. Canonical trailing bytes rejected.
KNOWN: reference idle-send about5s; health flag after33s, polled by control30s.
OBSERVED: same-socket port migration failed in bounded tests; broader policy UNKNOWN.
Evidence: E0022/E0044, V0003. Timers remain caller-owned.

### AES_DATA — type0

Direction C↔S; requires installed cipher slot, normally Active/overlap.

| Field | Offset | Size | Meaning |
|---|---:|---:|---|
| Magic |0|1|0x4b|
| unknown_flags_1 |1|1|sender emits0; receive semantics UNKNOWN|
| Type |2|1|0|
| Slot |3|1|0/1|
| Nonce |4|12|random bytes|
| Authentication tag |16|16|GCM tag|
| Ciphertext |32|remaining|encrypted inner representation|

AES-128-GCM, empty AAD, key16. Header is unauthenticated. Tag precedes ciphertext.
V1 plaintext: EtherType:u16be followed by network payload. V2–V4 add trailing
sequence:u32be. Ethernet source/destination MAC bytes are not in the ciphertext.
Library structural minimum34; authenticated V2–V4 plaintext minimum6.
No proprietary compression/fragmentation established. Inner IPv4 fragmentation is
OBSERVED; this crate neither reassembles nor interprets IP packets.

Authentication failure drops plaintext without consuming replay state. Wrong slot
fails before crypto; wrong key fails tag verification. A wrong session cannot be
identified by an invented session header; application chooses key/peer ownership.
Both directions use the same installed key. Legacy cipher kind0 is not implemented:
its full safe wire semantics are not established for this library.
Evidence: E0018–E0021/E0038/E0057; synthetic AES vector and lab data tests.

### Replay and rotations

KNOWN: per-slot last0 and empty seen map on installation; sequence0 rejected.
Window64: latest accepted once, unseen reordered last−63 accepted, last−64 rejected.
Reject sequences>0xffffffbf without wraparound. Authenticate before updating.
Transmit starts at1 for V2–V4. V1 has no established encrypted sequence branch.
Rotation threshold counters>0x02000000 or deadlineCEP/2; caller schedules deadlines.
Promotion changes primary without resetting the slot. Replace DataCipher to install.
Evidence: E0020/E0021/E0025/E0037/E0038 and bounded replay/rotation lab observations.

## Explicit ordering

`Initial → VersionReply → Username → UsernameResult → Password → PasswordResult
→ InitialConfig → IpConfig → UdpBinding → Active → Closed`.
Only sender/receiver combinations above are accepted. Authentication/setup ERR
closes the modeled handshake. Active accepts client key changes and keepalives,
server key acknowledgments, keepalive responses, routes and unknown messages.
No explicit disconnect opcode is established; caller invokes close on EOF/failure.
No wire action is emitted by transitions. No browser, user, network or timer policy
exists here. Evidence: E0007–E0017/E0023–E0025/E0043.

## Remaining unknowns and readiness

Secret generation/lifetime, complete error registry, non-ASCII credentials, broad
metadata/flags policy, peer IPv6, long-term expiry, NAT migration and termination
remain UNKNOWN. This version provides structural types for EtherTypes without
claiming IPv6 peer support. The reference adapter's IPv6 filtering is local behavior.
The server must validate and test its policy using an authorized client/capture
matrix before declaring production compatibility.

Every discovery follows observe → hypothesis → controlled experiment → capture →
compare → prove/refute → document → implement → test. Synthetic vectors are labeled
as such. Add sanitized fixtures for new facts and regression tests for fuzz crashes.
