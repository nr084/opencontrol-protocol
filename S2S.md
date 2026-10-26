# Certificate-selected Site-to-Site profile

This recovered endpoint profile is separate from username/password client mode;
it is not IPsec. The TLS adapter authenticates a presented client certificate and
selects the role. USER or OS metadata cannot switch roles. Historical MD5
certificate fingerprint matching is observed compatibility behavior, not a
recommended universal trust policy. The library contains no TLS implementation.

The TLS acceptor sends VERSION22 first, initiator replies, acceptor sends16,
initiator17, acceptor18. Initiator sends UDP CONNECT using the new secret, acceptor
sends7 after validating it; both become Active. `EndpointRole` determines these
directions; `Flow` is relative to the local endpoint.

| Message | Exact payload |
|---|---|
|16 IPCONFIG_1|IPv4 address4, mask4|
|17 IPCONFIG_2 success|address4, mask4, error0, CEP:u16be, cipher config; AES32 bytes, legacy39|
|17 rejection|address4, mask4, nonzero error, CEP:u16be, opaque kind, slot; exactly13 bytes, no installed cipher|
|18 IPCONFIG_3|CEP:u16be, secret128;130 bytes|

`EndpointMachine` models both initiator and acceptor. `ProtocolSession` also installs
keys, tracks binding, deadlines and epoch-fenced callbacks. Known refusals15/20/21
are wire opcodes, with opaque payload, not a complete local error-code registry.
Duplicate15 can precede VERSION; do not assume the previous connection survives.

Active both sides may send8/9/10/19. S2S Q10 does not require R11. Received Q10 or
Q8 refresh control liveness; UDP traffic does not. Native acceptor/initiator rekey
scheduling is asymmetric in the observations; do not infer symmetric behavior from
a shared CEP field. Our optional sender schedules CEP/2 and counter threshold;
only one proposal is outstanding, collision/missing ACK requires reconnect.
ACK has no transaction ID. See [migration](MIGRATION.md).
Incoming fresh Q8 may replace the current slot (observed first native initiator
rotation). Install its receive generation, write/observe R9 before sending data;
ProtocolSession/KeySlots enforce that send barrier. Locally proposed rotations use
the secondary slot. Replacing a slot retires its previous key/replay generation.

S2S route profile interprets START/END only. Lists span255-record frames and may
aggregate up to configured4096. `/24` and nested `/25` coexist; exact-prefix
ownership is first-advertiser-wins. The observed peer did not transfer a conflicting
prefix automatically within4 seconds of withdrawal; repeating the surviving
advertisement restored it in both orders. `Unchanged` must not suppress outgoing
advertisement or OS retry. Use `advertisement_batches` and `RouteApplications`.
Do not generalize a complete subnet-conflict or traffic-failover table from this.
