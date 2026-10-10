# Fixture provenance

All fixtures here are synthetic. Control literals derive from E0004/E0008/E0009/
E0011/E0023, indexed in the project research area. Credentials are the public
example strings `alice` and `example`; no production input is included.

`negative/` contains intentionally incomplete or invalid outer stream frames.
These are checked at decoder/EOF level. Known message invalid enums, credentials,
TLVs and version-dependent payloads are covered by deterministic integration tests.
Bad auth tags, wrong key/slot, invalid sequences and replay are covered by crypto/
datagram tests; a wrong session has no independent wire session-ID field.

`../vectors/synthetic.json` contains exact control and datagram bytes and the
independently cross-checked AES vector. The AES plaintext is intentionally not a
valid IP packet. It tests EtherType and sequence placement without inventing IP
semantics. `../vectors/handshake_v4.bin` is the state-fuzzer transcript seed, with
the developer record envelope documented in TESTING.md, not a wire capture.
