# Migration from 0.2.x to 0.9.0 / Переход с 0.2.x

```toml
opencontrol-protocol = { git = "https://github.com/nr084/opencontrol-protocol.git", tag = "v0.9.0", version = "=0.9.0" }
```

Update the consumer lockfile and remove an obsolete pinned `rev`. The crate version
is independent of product, TLS and wire versions. Stable Rust/MSRV remains 1.99.

## Breaking changes

- `ControlMessage` has new typed variants: route query/replies, wire failures,
  legacy configuration and S2S16/17/18. Update exhaustive matches. They no longer
  decode as `Unknown`; constructing `Unknown` for a known opcode is rejected.
- `ProtocolLimits` adds `max_route_entries` (default4096). Use a struct update
  `..ProtocolLimits::default()` for custom limits. `max_collection_items` remains
  the per-frame bound (at most255 route records), not the session aggregate.
- A second outgoing key proposal while awaiting R9 returns `RekeyPending`.
  It cannot overwrite an unacknowledged proposal. An unsolicited R9 is ignored.
- Initial wire3/4 metadata must contain a NUL in its128-byte description field.
  Use `ClientMetadata::new(version, build, os_code, description)`; maximum127 UTF-8
  bytes, no embedded NUL. Raw byte arrays remain available for exact parsing.
- Client ACTIVE receive policy permits the separately observed3/4/22/10/11 sequence.
  Use `incoming_event` or `ProtocolSession::observe` to distinguish ignored messages
  from authentication errors. Handshake rejection remains terminal.

## Sessions, keys and cancellation

Existing low-level codecs/`RouteState`/`DataCipher` remain usable. For coordinated
lifetime management use `connection::ProtocolSession`: choose ClientServer or
SiteToSite profile, supply monotonic milliseconds, and observe incoming messages
once, outgoing messages only after a successful send. Its `SessionEpoch` fences
local callbacks; it is never serialized into a wire header. `reconnect` resets
handshake, keys, replay, pending ACK, endpoint and binding. Retain old OS ownership
separately until acknowledged cleanup finishes.

`KeySlots` owns both cipher slots and per-install generations. Promotion retains
the old slot until replacement or session close; there is no invented30/60-second
retirement timer. Fresh key material is required. R9 has no transaction ID.
The native S2S initiator may replace its currently selected slot with a fresh key,
including its first immediate Q8. Incoming same-slot replacement is supported;
data sends return RekeyPending until the adapter writes R9 and observes that send.
This retires that slot's old generation immediately. Our outgoing proposals still
select the secondary slot, preserving current transmit state while awaiting ACK.
Do not send another local proposal until ACK. `ProtocolSession` closes on a
20-second missing-ACK deadline or simultaneous opposite-direction proposal:
reconnect with fresh keys/binding rather than guess which proposal was acknowledged.
This is our conservative safety policy, not a claimed native wire timer.

Poll with caller monotonic time. Control and UDP liveness are separate; arbitrary
UDP traffic does not renew the control deadline. `close` cancels actions, drops keys
and exposes a5-second transport-close deadline. The adapter must stop reads/writes,
bound TLS shutdown and close its sockets even if the peer never sends EOF.
An endpoint address/port change requires a new binding/session; no seamless NAT
migration is promised. TLS verification and certificate-selected S2S role stay
in the adapter.

## Continuous ROUTES and OS acknowledgment

Never return a configuration error merely because another ROUTES arrived.
Keep one tracker for the session, including initial and empty messages. `Changed`
and `Unchanged` describe effective logical state, not OS success. Commit valid
messages even when an OS operation fails; use `route_application::RouteApplications`
to record desired versus applied resources and retry individual operations.

Register the epoch/profile and the original endpoint uplink. On every incoming
ROUTES call `receive(owner, &routes)`, then `begin_plan(owner)` regardless of
`logical_changed`. A START batch is staged until END before OS application.
Execute the returned operations in order, stop after failed endpoint protection,
and `acknowledge(plan.id(), &operation_successes, status_success)` with actual
results. Also retry on the platform's retry timer without waiting for another
network message. Never report a failed operation as successful.

An identical logical list may now require retry or reclaiming a formerly competing
prefix. Outgoing `routes::advertisement_batches` deliberately emits a full list on
every call, including identical reannouncements. `/24` and nested `/25` coexist.
Use `withdraw`, repeated plans/acknowledgments, then `forget`; failed removal must
retain ownership. See [integration contract](ROUTES_INTEGRATION.md).

## Legacy and S2S

Enable both Cargo `features = ["legacy"]` and runtime
`LegacyPolicy::ExplicitlyEnabled` only for an explicitly configured compatibility
profile. There is no automatic downgrade. `Integrity::UnkeyedChecksum` and
`NoIntegrity` are weaker than `Authenticated`; do not present them as GCM security.
See [legacy](LEGACY.md) and [S2S](S2S.md).

## Android: обязательное изменение потребителя

Android-проект в этом выпуске не меняется. В `transport.rs::pump` обязательно
заменить `ControlMessage::Routes(_) => return Err(EngineError::Configuration)`.
Обновление зависимости само по себе этот разрыв не исправляет.

На протяжении сессии передавать каждый ROUTES одному tracker/coordinator, включая
первый и пустой список. `Unchanged` — успешная обработка: сохранить TUN, TLS, ключи,
счётчики и replay windows. При этом проверять необходимость retry ранее неудачных
операций ОС. `Changed` передавать в новый подтверждаемый контракт Platform/JNI
вместе с полной актуальной конфигурацией и отдельным safeLan status. Не строить
настройки только из записей последнего wire-сообщения. START без END не применять.

Если VpnService требует новый FD при реальном изменении маршрутов, платформенный
слой готовит замену, проверяет FD, сохраняет старый TUN до успешной установки и
возвращает фактический результат. Замена TUN не требует нового protocol-сеанса.
Ошибку применения учитывать отдельно, повторять или явно восстанавливать, не
терять сведения об уже добавленных ресурсах. Сохранить IP, DNS, domain, MTU,
connected subnet и защиту сокетов независимо от серверного списка маршрутов.
safeLan не включает блокировку LAN/firewall. Входящее сообщение наблюдать автоматом
ровно один раз. Старый подробный [0.2 Android sketch](ANDROID_MIGRATION.md)
исторический: его clone/commit-after-platform подход заменить подтверждением
desired/applied, особенно при многочастных обновлениях и частичных ошибках ОС.

Все приложения сохраняют ответственность за TLS, сертификаты, сокеты, TUN/TAP,
системные маршруты, DNS, firewall, повторные попытки и долговечный журнал владения
ресурсами. Сборка и публикация Android/сервера не входят в этот выпуск.
