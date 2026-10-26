# Implementation checkpoint — 0.9.0

Target: v0.9.0, existing public opencontrol-protocol repository. Core is synchronous
and independent of platform applications. Research closure2026-10-26 supersedes
historical UNKNOWN/plans; IMPLEMENTATION_MATRIX.md maps findings to code/tests/docs.

Implemented: continuous atomic ROUTES, bounded multipart aggregation, safeLan status,
full-tunnel endpoint ownership, desired/applied acknowledgment and retry; Q12/R13/R14;
state-dependent client ACTIVE handling; exact AES and explicit optional legacy;
S2S16/17/18 and initiator/acceptor machines; two key slots/generations, local epochs,
fresh reconnect/binding, conservative ACK/collision deadlines; caller-clock separate
liveness/cancel; literal UTF-8 and bounded OS metadata; explicit IPv6 limitations.

Breaking changes and mandatory consumer work are in MIGRATION.md. Android and server
source/releases remain outside this task. No crates.io publication is authorized.
Tests of the new library and measured integration results are recorded in VALIDATION.md;
old0.2 hourly metadata is historical, not proof of0.9 operation.

Limits: no complete product/platform matrix, IPv6 configuration, seamless NAT migration,
full subnet-conflict table or unlimited observed key overlap. The coordinator retains
old slot until replacement/session cleanup without inventing a TTL. Legacy is weak
integrity, not authenticated GCM. OS/DNS crash recovery requires the application.
