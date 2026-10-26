# Explicit legacy compatibility

Cipher kind0 uses Blowfish counter-mode keystream, not CBC. Kind1 is AES-128-GCM.
Wire version4 does not select a cipher; the negotiated configuration does. Sampled
product9.2.7 uses legacy and9.2.8+ uses AES. The TLS ciphersuite selects neither.

Build with `features=["legacy"]` and select runtime
`LegacyPolicy::ExplicitlyEnabled`. Both are required. No error triggers downgrade.
`LegacyInitialConfig`, `LegacyKeyChange` and `AnyCipherConfig` represent exact wire
formats even in a build that refuses legacy packet processing.

Legacy config is `kind0 | slot | 10 08 | key16 | salt8`; Q8 payload28 bytes.
Initial Q5 payload30 bytes for V1/2,167 for V3/4. AES lengths are21 and23/160.
UDP is `4b 00 00 slot | 08 | (counter8 XOR salt8) | ciphertext`.
The little-endian counter is incremented for every8-byte Blowfish-ECB-generated
keystream block and XORed with plaintext. Counter wrap is rejected. Each new
cipher object chooses a random initial counter; this does not provide authentication.

Plaintext begins with a big-endian length covering the following body, excluding
the length and FF padding to an8-byte boundary. V1 body is EtherType+packet;
V2–4 append sequence:u32be and one's-complement BE checksum:u16be. The checksum is
computed over EtherType+packet+sequence with an odd final byte zero-padded for
the calculation. Compare the received checksum separately; do not assume the
whole odd-sized body sums to zero. Legacy padding is validated strictly.

V1 returns `Integrity::NoIntegrity`; V2–4 `UnkeyedChecksum`, never `Authenticated`.
An attacker can modify a checksum-protected packet. A successful checksum precedes
replay updates but is not a MAC. Prefer AES and authenticated TLS in new profiles.

Synthetic [vectors](protocol/vectors/legacy_synthetic.json) cover all four wire
versions with odd/even packets. The independent Python ECB generator is
[tools/generate-legacy-vectors.py](tools/generate-legacy-vectors.py).
No laboratory keys are included. RustCrypto `blowfish`0.10 is MIT OR Apache-2.0,
MSRV1.85, optional with its `zeroize` feature; core project MSRV stays1.99.
Original source/license: [RustCrypto block-ciphers](https://github.com/RustCrypto/block-ciphers/tree/master/blowfish).
