# Live ROUTES diagnostic

Standalone developer client using the local opencontrol-protocol0.2.0 dependency.
It is excluded from the core workspace: TLS/socket/runtime dependencies are not
introduced into the library. The leaf certificate verifier follows the existing
Android explicit-pin adapter, including validity dates and TLS signature checks.
The previously trusted DER certificate must be supplied; there is no TOFU mode.

The tool requires an authorized test account. Username/password arrive on stdin,
not argv, and are not logged or stored. Do not pass real credentials in chat.
The Windows wrapper prompts for the password with Read-Host -AsSecureString and
transfers it directly to the process. Managed-runtime copies cannot guarantee erasure.

```powershell
./tools/run-routes-live.ps1 -Server <lab-ip>:4090 -TrustedCertificate <trusted-leaf.der> -Duration 1265
```

Duration is actual wall-clock21+ minutes. The diagnostic expects initial ROUTES and
at least two later unchanged ROUTES on the same TLS/UDP session. It continuously
exercises authenticated IPv4 ICMP traffic to the negotiated VPN gateway, keepalive
and ordinary key rotation. Reports contain counters, numeric route flags/counts,
elapsed times and slot selection; no credentials, keys, secrets or full payloads.
No TUN, OS routes, server settings or Android source are changed.

Use Duration3665 for a continuous61-minute run with six expected600-second repeats.
Duration is bounded1260..7200 seconds; the required repeat count scales with duration.

`oc-routes-live --check-tls host:port trusted-leaf.der` performs a credentials-free
TLS preflight. Its success establishes trust/reachability only, not VPN authentication
or periodic ROUTES behavior.

A passing library diagnostic does not prove Android platform migration. Real route
changes and OS/FD application require the separate client acceptance matrix.
The program produces JSONL events; only a final summary with passed=true establishes
that its defined live criteria passed. A compiled executable is not a successful test.
