# ROUTES maintenance clarification — 2026-10-13

Static clarification of the existing E0024 path, not a new live-server observation.
Relevant code is in the separate research area's raw/routes-data-variants.txt.
The committed routes-maintenance.txt excerpt additionally resolves its helper calls.
No executable source, credentials, session material or private endpoint is included.

| Function | Confirmed operation |
|---|---|
|93fa0 /94078|flag bit0 calls99010 before applying records|
|99010 /99040|starts maintenance and calls98e00|
|98e00 /98e1f|clears the touched byte for all existing entries; does not immediately remove them|
|92410 →99660|applies network/mask entries;996d1 touches existing equal records instead of duplicating them|
|93fa0 /940c0|flags&9==9 applies the two default-covering /1 records|
|93fa0 /94050|flag bit1 calls99070 after records and generated defaults|
|99070 /99088|calls98e30 to finish maintenance|
|98e30 /98e6c–98e81|removes untouched nonpersistent entries; caller-owned local routes are not library state|
|93fa0 /93ffd–94039|bit2 supplies the observed safeLan status callback (E0056)|

The earlier shorthand "bit0 clears; bit1 disables full routing" was inaccurate:
bit0 marks the list for replacement; bit1 finalizes removal of stale entries.
Full coverage disappears on a completed replacement that omits default routes,
not simply because bit1 is set. Multiple batches may touch routes between start
and finish. The library tracks their effective union until final pruning.

Reproduction (read-only static disassembly; no reference executable is executed):

```text
query.py func 93fa0 92410 99010 99070 98e00 98e30 99660
```

The /1 constants and original flow are covered by E0024. Unknown high flag bits
remain metadata. No mapping is asserted between textual server flag abbreviations
and numeric wire bytes without a capture. A user-reported 600-second repeat/drop
timeline motivates synthetic regression vectors but is not a new captured fixture.
