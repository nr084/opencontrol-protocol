# 0.9.0 evidence-to-implementation matrix

Research is read from the separate reverse workspace; its current 2026-10-26
closure supersedes historical plans. No private lab logs or binaries are copied.

| Finding | 0.2 baseline | 0.9 change | Validation | Documentation |
|---|---|---|---|---|
|E0004/SC0020 framing|bounded incremental codec|retain strict magic/63999 limit|fragment/coalesce/EOF/bounds/fuzz|PROTOCOL|
|C0019 ACTIVE3/4/22/10/11|some rejected|explicit client receive disposition; handshake remains strict|each opcode followed by ROUTES|PROTOCOL/MIGRATION|
|SC0001/6/7 route query12/13/14|opaque|typed count-only reply, bounded query tracker|golden/zero-progress/end|PROTOCOL|
|E0024/SL0010/SC0027 ROUTES|tracker limited to255 aggregate|4096 aggregate, deferred START/END OS plans, owner identity|256 batches, duplicates/withdraw/conflicts|ROUTES_INTEGRATION|
|SC0024 safeLan|status bit preserved|separate status event; no enforcement|3/7/7/3 independent of full tunnel|PROTOCOL|
|C0020 uplink endpoint|caller responsibility|plan endpoint /32 and owned cleanup, retain across split|mock OS/retry/foreign routes|ROUTES_INTEGRATION|
|CV0004/7 legacy|unsupported|feature + runtime opt-in; exact counter/salt/checksum|independent vectors/wire1..4/replay|LEGACY/SECURITY|
|E0019/CV0010 AES|AES128/GCM|retain exact profile, no AAD or TLS-suite inference|golden/tag/replay/generations|PROTOCOL|
|CV0008/9,SC0025 keys|caller-managed|two-slot epoch-fenced coordinator; no old-slot TTL|replace/retain/reconnect/stale ACK|MIGRATION|
|E0050/T0008 R9 race|latest pending promotion|one outbound proposal; explicit collision/reconnect errors|late/unsolicited/multiple/reverse roles|MIGRATION|
|0.9 acceptor live Q8|secondary-only receive rejected native first rotation|fresh same-slot peer replacement; send barrier until R9|deterministic regression +72s acceptor,3 peer rotations|S2S/MIGRATION/VALIDATION|
|ST0001/2/3/SL0004 S2S|unsupported|separate initiator/acceptor machine,16/17/18 codecs|both roles/failure/peer rekey|S2S|
|SL0013/SC0026 liveness|application only|caller-clock deadlines, cancellation, separate control/UDP|virtual time/backwards/deadlines|MIGRATION|
|CE0001..5 credentials|opaque bytes, NUL rejected|UTF-8 convenience, no transforms|Unicode/NFC/NFD/space/130-byte password|PROTOCOL|
|S0006 OS metadata|raw field|bounded NUL-terminated UTF-8 constructor, safe emission|127/128/multibyte/NUL|MIGRATION|
|I0011..13 IPv6|generic EtherType|explicit capability distinction, unsupported negotiation error|generic envelope succeeds, negotiation unsupported|README|
|C0015..20 platform faults|candidate clone example|desired/applied acknowledgment, retry/cleanup ownership|partial-failure mock and cancellation|ROUTES_INTEGRATION|

Core remains socket/TLS/clock/OS independent. Tests and examples exercise library
behavior; historical probe/native measurements are attributed separately. Current
library live results are recorded only after executing the new build.
