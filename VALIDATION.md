# Validation — OpenControl Protocol 0.9.0

Date:2026-10-26. Stable Rust1.99.1 on Windows and clean Ubuntu x86_64 VM;
nightly1.101.0 (2026-10-26) for Linux sanitizer smoke. No crates.io publication.
Only library sources, synthetic fixtures and sanitized aggregate results are public.
Raw lab logs, test credentials, temporary TLS keys and private IPs are excluded.

## Automatic checks

- Stable fmt, default/all-feature clippy with `-D warnings`: pass.
- Default/all-feature workspace/all-target tests, documentation tests, strict rustdoc:
  pass. All-feature suite includes48 unit/integration/example tests plus2 doctests.
- Standalone live adapter: build/check/clippy on Windows, S2S adapter built on Linux.
- Executable client_routes: virtual0/600/1200, full/split endpoint protection,
  partial-failure retry and acknowledged owned cleanup: pass; no real OS writes.
- All four fuzz targets compile on Windows. Linux actual nightly sanitizer smoke,
  15-second budget each: control289211, datagram3544910, state750221 executions;
  session55381 initially,52598 after adding server-role coverage,47756 after the
  same-slot peer replacement correction. No crash found.
  These are short smoke campaigns, not an exhaustive security proof.
- Linux all-feature/all-target tests pass on the final behavioral source.

Tests reproduce C0019 ACTIVE3/4/22/10/11 then ROUTES, exact wire1–4 AES/legacy
configuration, CEP1800 repeated empty ROUTES at600s before rekey, invalid-message
atomicity,256-route segmentation, ownership/conflicts/reannouncement, partial OS
failures, replay/key replacement/reconnect, UTF-8/NUL/metadata bounds and separate
deadlines/cancellation. See TESTING.md and IMPLEMENTATION_MATRIX.md.

## New-library live integration

The new0.9.0 dependency is called by standalone adapters, not by the old native
client or a Python implementation of packet crypto. Python only manages a uniquely
named temporary S2S interface/certificate and validates cleanup around Rust execution.

- S2S initiator, AES:72 seconds,36 valid decrypted ICMP echoes and one local proposal
  acknowledged; pass.
- S2S initiator, explicitly enabled legacy:72 seconds,36 checksum-valid ICMP echoes,
  local transition to fresh AES acknowledged; pass. Legacy is not authenticated GCM.
- Peer-initiated Q8 was not observed during those initiator windows. This agrees with
  the separately measured asymmetric native scheduling; those runs do not certify
  the reverse direction. Both directions are tested deterministically.
- Temporary S2S interface was removed; pre/post interface ID sets matched.
- Client profile, actual1265.013 seconds with CEP1800: two periodic empty ROUTES
  at599.596 and1199.761 seconds, both Unchanged;249/250 valid authenticated echoes,
  42 keepalive responses, one acknowledged rekey around900s, zero reconnects.
  The session stayed Active with traffic after the second update. One echo had
  no matching reply; this is not reported as100% delivery. No rekey preceded the
  first periodic update. The echo adapter uses library StateMachine, RouteState
  and KeySlots; S2S adapters additionally exercise ProtocolSession.
- S2S acceptor on the reset Ubuntu VM, final corrected library:72 seconds,35 valid
  decrypted ICMP replies, three native peer Q8 rotations and one local proposal
  acknowledged. Thirty replies followed both directions of rekey; pass.
  Temporary interface/certificate files removed; interface ID sets matched.

An early diagnostic adapter run misclassified plaintext UDP keepalive as encrypted
data and stopped. The adapter was corrected to discriminate UDP type0; the full
run was restarted. This is not reported as a successful run or a core decoder defect.
An initial S2S assertion incorrectly required a peer rekey within72s; it was corrected
against the prior asymmetric evidence. Actual local rekey/data acceptance remained
required and passed in repeat runs.

OS routes/DNS/TUN/firewall are represented by mocks and documented contracts, not
applied in live echo tests. No Android/server/platform product release is tested.
Only the available reference build and wire4 are live-tested; other wire versions
use exact synthetic fixtures. No full IPv6, all-product compatibility, seamless
NAT migration, complete subnet-conflict table or indefinite overlap is claimed.

An initial acceptor run found a real compatibility defect in the new coordinator:
its strict secondary-only receive rule rejected the native initiator's immediate
fresh Q8 replacing the current slot. Incoming same-slot replacement now installs a
new receive generation and blocks data sends until R9 is written/observed; local
proposals still use the secondary slot. A deterministic regression was added and
the repeated acceptor integration passed on the corrected source.

## Historical0.2 evidence

The committed interop/routes-periodic-hour-20261013.json records a61-minute0.2
run with six periodic updates. It is retained as historical sanitized evidence and
regression input, and is not used to claim that0.9 passed a61-minute test.
