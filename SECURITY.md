# Security properties and limits

All application bytes must arrive through a caller-authenticated TLS transport.
The library has no certificate policy and must not be used to send credentials
over an unauthenticated transport. Passwords are literal terminated byte strings;
no challenge or password KDF is present in the observed exchange.

AES-128-GCM uses 12-byte OS-random nonces and 16-byte tags, with empty AAD.
The UDP header is not authenticated by this wire format. The same key is used
in both directions, as observed. Do not invent directional derivation or AAD when
interoperating. Random IVs have collision risk; caller-managed rotation remains
necessary. `needs_rotation` indicates the observed counter threshold; callers also
schedule the observed CEP/2 deadline. The library does not enforce a key lifetime.

GCM authentication precedes replay updates. V2–V4 use a 64-packet receive window;
V1 has no demonstrated sequence protection. Reinstalling a key resets replay state.
Never reinstall a previously used key casually: observed peer behavior admits old
ciphertexts after same-key installation. The state machine models uncorrelated R9
acknowledgments; applications must consider ambiguity during multiple outstanding
rotations. Neither replay state nor a UDP header establishes session identity.

SessionKey and BindingSecret zeroize owned arrays on drop. Temporary cipher config
buffers and decrypted plaintext are zeroized. Debug output redacts credentials,
secrets, frame payloads and message payloads. No core logging exists.
Credential/frame/encoded TLS bytes use reference-counted Bytes and cannot guarantee
erasure of all copies. RustCrypto expanded cipher state, stack copies and caller
copies are not guaranteed erased. Avoid logging or retaining these buffers.

Strict framing and size/collection limits reduce memory abuse. Decoder errors are
terminal for that decoder; application policy decides whether to close the transport.
Peer rate limiting, session expiration, authentication policy, secret generation,
CONNECT constant-time matching and endpoint ownership belong to the server.
No scalar wire session ID or authenticated header has been established.

Report security findings privately to the project owner; no public disclosure
endpoint is configured yet. Do not include production credentials or session keys
in issue reports, fixtures or fuzz corpora.

