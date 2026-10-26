# OpenControl Protocol Library 0.9.0

## Русский

Выпуск объединяет результаты исследования протокола и исправляет интеграцию
повторных ROUTES: постоянное состояние, START/END, пустые списки, safeLan и полный
туннель. Добавлены desired/applied планы с подтверждением, retry и владением.

Также реализованы запросы маршрутов12/13/14, политика сообщений в ACTIVE,
явно включаемый legacy Blowfish, S2S в обеих ролях, два ключевых слота и поколения,
epoch-защита reconnect, таймеры/отмена, точные UTF-8 реквизиты и metadata ОС.
Живой S2S-тест обнаружил и помог исправить замену текущего слота ключом peer:
приём нового поколения разрешён, отправка данных ждёт отправленного R9.

Проверки: stable Rust1.99.1, fmt/clippy/tests/docs/examples;50 автоматических тестов
с all features и doctests; четыре Linux nightly sanitizer fuzz smoke без сбоев.
Живой клиентский тест1265 секунд, CEP1800: два повторных ROUTES без изменений,
249/250 проверенных echo-ответов, один rekey, без переподключений. S2S initiator:
AES и legacy по72 секунды/36 ответов; S2S acceptor:72 секунды/35 ответов,
три peer rekey и один локальный ACK. Конфигурация временного туннеля восстановлена.

**Breaking changes:** варианты ControlMessage, ProtocolLimits.max_route_entries,
строгая NUL-терминация metadata, один ожидающий ACK локальный rekey.
[Миграция, включая обязательное изменение Android](https://github.com/nr084/opencontrol-protocol/blob/v0.9.0/MIGRATION.md).
Одно обновление зависимости не исправляет завершающий обработчик ROUTES в клиенте.

Ядро не управляет TLS, сокетами, TUN, DNS, маршрутами ОС или firewall. Полный IPv6,
все версии продуктов и бесшовная NAT-миграция не заявлены. Legacy checksum — не MAC.
Android и сервер не выпускаются; crates.io не используется.
[Подробный отчёт и ограничения](https://github.com/nr084/opencontrol-protocol/blob/v0.9.0/VALIDATION.md).

## English

Persistent ROUTES state now separates logical updates from acknowledged OS application,
including empty/segmented lists, safeLan status, full-tunnel endpoint protection,
retry and resource ownership. Repeated unchanged updates keep sessions and keys intact.

Adds typed route queries12/13/14, state-dependent ACTIVE handling, explicit legacy
Blowfish compatibility, both certificate-selected S2S roles, two-slot/generation
coordination, epoch-fenced reconnect, caller-clock deadlines/cancel, exact UTF-8
credentials and bounded OS metadata. Native same-slot peer key replacement is
supported with a data-send barrier until R9 has been sent.

Validation: stable Rust1.99.1; fmt/clippy/tests/docs/examples;50 all-feature tests
including doctests; four Linux nightly sanitizer smoke targets. Actual1265-second
client session at CEP1800 survived two periodic ROUTES and one rekey without reconnect
(249/250 validated echoes). Both S2S roles and explicit legacy were live-tested;
see the linked validation report for exact scope and intermediate fixes.

Breaking API changes and mandatory consumer migration are documented above.
The core owns no transport or OS configuration. No full IPv6/all-product coverage,
seamless NAT migration or authenticated legacy security is claimed. GitHub release
only; no crates.io or platform application release.

```toml
opencontrol-protocol = { git = "https://github.com/nr084/opencontrol-protocol.git", tag = "v0.9.0", version = "=0.9.0" }
```
