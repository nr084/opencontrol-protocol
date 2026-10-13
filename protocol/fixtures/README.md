# Fixture provenance

Control/negative byte fixtures are synthetic. Control literals derive from E0004/E0008/E0009/
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

`interop/server_v4_idle.json` contains measured lab metadata without wire payloads,
credentials or keys. It records downstream V4 acceptance of the existing canonical
UDP Keepalive reply and references the server acceptance report.

`interop/routes-periodic-hour-20261013.json` contains observed metadata from an
actual3665-second standalone0.2.0 client run against the reference-server lab:
six unchanged ROUTES,725/725 authenticated echoes,121 rekeys, no reconnect.
It includes source/executable hashes and scoped limitations, but no endpoint,
account, credentials, key/secret or raw application bytes. It is not a PCAP or
raw golden frame capture. The regression reconstructs its empty route messages.
