# Security properties and limits

The adapter must authenticate TLS before sending literal username/password bytes.
S2S role requires a client certificate and its own trust policy; library codecs do
not validate certificates. Historical fingerprint matching is not a modern default.

AES-128-GCM uses key16, OS-random nonce12, tag16 and empty AAD. Header bytes are
unauthenticated; both directions share the installed key as observed. TLS suites do
not select the UDP cipher. Rotation by CEP/2 and packet threshold limits nonce risk;
no arbitrary key TTL is inferred. Authenticate before updating replay windows.
V2–4 have a64-packet per-slot/per-generation receive window; V1 has no sequence.

Legacy requires explicit feature and runtime opt-in, never automatic downgrade.
Its checksum is unkeyed and malleable; V1 has no integrity. API integrity labels
separate it from authenticated GCM. Counter wrap and invalid padding/length/checksum
are rejected. See LEGACY.md for exact format and dependency provenance.

KeySlots rejects reuse of current material, retains the old slot through promotion,
and retires it on replacement or close. Fresh keys must be generated for every
installation; do not recycle historical material. R9 has no correlation ID. Only
one local proposal may be pending. ProtocolSession closes on opposite-direction
collision or20-second missing ACK and requires a fresh reconnect rather than guessing.
Old keys/windows/binding/pending state are dropped; local epoch fences old callbacks.
Changing peer port does not silently migrate a binding. No wire session ID is invented.

Owned SessionKey, BindingSecret, LegacyKey and temporary decrypted buffers zeroize
on drop; optional Blowfish expanded state uses its zeroize feature. Diagnostic Debug
redacts secrets. Bytes, caller copies, stack copies and AES expanded state cannot
all be guaranteed erased. Do not log raw frames, credentials or encoded secret payloads.

Control and UDP health are distinct. Cancellation drops protocol secrets immediately;
transport must honor the exposed bounded close deadline rather than await EOF forever.
OS routes and resolver state remain the adapter's responsibility. In-memory ownership
and acknowledgment support retry but do not provide durable crash recovery or protect
against unrelated external writes without reconciliation/locking.

Strict framing, bounded collection/resource counts and typed errors limit untrusted
allocation. Native header resynchronization, embedded credential NUL truncation,
unsafe unterminated metadata and latest-pending ACK races are deliberately not copied.
The endpoint must still enforce authentication, rate limits and resource policy.

Report security findings privately to the repository owner. Do not include production
credentials, laboratory logs, extracted binaries or session secrets in public issues,
fixtures, releases or fuzz corpora.
