# OpenControl Protocol Library

[English](README.md) · **Русский**

[![Library quality](https://github.com/nr084/opencontrol-protocol/actions/workflows/quality.yml/badge.svg?branch=main)](https://github.com/nr084/opencontrol-protocol/actions/workflows/quality.yml)

Независимая Rust-библиотека кодеков и состояния исследованного OpenControl Protocol.
**Crate: `opencontrol-protocol` · Версия 0.9.0 · Wire 1–4 · MIT · последний stable Rust.**

```toml
[dependencies]
opencontrol-protocol = { git = "https://github.com/nr084/opencontrol-protocol.git", tag = "v0.9.0", version = "=0.9.0" }
```

Распространение через GitHub; публикации в crates.io нет. Сохраняйте Cargo.lock
приложения. Версии библиотеки, продукта, wire protocol и TLS независимы.

## Реализовано

- Ограниченный инкрементальный framing: фрагментация, объединённые чтения и EOF.
- Типизированные настройки, запросы маршрутов12/13/14, отказы и неизвестные сообщения.
- Политика сообщений по состоянию, включая нетерминальные ACTIVE 3/4/22/10/11.
- Постоянный tracker ROUTES: пустые, повторные, дополнительные и многочастные списки.
- Desired/applied планы маршрутов: владение, подтверждение, retry, защита endpoint.
- AES-128-GCM, точный UDP envelope, replay windows отдельных слотов и поколений.
- Явно включаемая совместимость с legacy Blowfish в счётчиковом формате.
- Отдельные S2S роли инициатора и принимающей стороны, кодеки и переходы состояний.
- Два ключевых слота, epoch-защита reconnect, передаваемое монотонное время и отмена.
- Точные UTF-8 реквизиты и безопасная терминация метаданных ОС от приложения.
- Синтетические векторы, регрессионные/property-тесты, примеры и четыре fuzz targets.

В ядре нет сокетов, TLS, async runtime, часов, TUN/TAP, DNS или firewall.
Приложение предоставляет проверенный транспорт, настройки ОС и надёжную очистку.
`ProtocolSession` координирует состояние без I/O; низкоуровневые кодеки и `RouteState`
доступны отдельно. См. [архитектуру](ARCHITECTURE.md).

## Повторные ROUTES

ROUTES приходит многократно в течение сеанса. Один tracker обрабатывает первое,
повторные и пустые сообщения. `Unchanged` — успех: сохраняйте ключи, replay state
и VPN-интерфейс. `Changed` содержит полную эффективную конфигурацию. Неизвестные
биты остаются непрозрачными; safeLan — статус, он не включает блокировку LAN.

Равенство конфигураций не означает успех применения ОС. `RouteApplications`
подтверждает каждую операцию и позволяет повторить неудачную даже при `Unchanged`.
START без END не применяется к ОС. До полного туннеля нужно сохранить доступ к
endpoint через прежний uplink. Очистка удаляет только собственные ресурсы.
Одинаковые исходящие объявления не подавляются, если требуется повторная отправка.

```sh
cargo run --example client_routes
```

Это детерминированный пример с mock-платформой, не живой тест. Одно обновление
зависимости не исправляет клиента, который завершает сеанс при ROUTES.
Обязательные изменения Android описаны в [миграции](MIGRATION.md); Android-проект
этим выпуском не изменяется. [Контракт маршрутов и DNS](ROUTES_INTEGRATION.md).

## Границы совместимости

API до 1.0. [Breaking changes 0.9](MIGRATION.md): варианты enum, лимит агрегации,
строгая терминация metadata и один ожидающий ACK rekey. Legacy требует одновременно
Cargo `features=["legacy"]` и runtime opt-in; checksum не является MAC.
[Legacy](LEGACY.md), [безопасность](SECURITY.md).

[S2S](S2S.md) — отдельный профиль с клиентским сертификатом, не IPsec. Проверка
сертификата и выбор роли остаются транспорту. Полная таблица конфликтов подсетей,
бесшовная NAT-миграция, все версии продуктов и бесконечная жизнь ключей не заявлены.
IPv6 EtherType представим в envelope, но IPv6-настройки и сквозная совместимость
не установлены. `Capabilities::require_ipv6_configuration()` возвращает явную ошибку.

[Отчёт](VALIDATION.md) разделяет тесты новой библиотеки и исторические исследования
probe/штатного клиента. Успешный echo не подтверждает применение ОС или работу
всех платформенных приложений.

## Документы и разработка

- [Протокол](PROTOCOL.md), [матрица реализации](IMPLEMENTATION_MATRIX.md).
- [Миграция](MIGRATION.md), [S2S](S2S.md), [маршруты/DNS](ROUTES_INTEGRATION.md).
- [Проверки](TESTING.md), [изменения](CHANGELOG.md), [состояние](PROJECT_STATE.md).

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked
cargo test --workspace --doc --all-features --locked
cargo doc --workspace --no-deps --all-features --locked
```

CI проверяет также default features и Linux nightly fuzz smoke. Короткий smoke
не заменяет длительную sanitizer-кампанию. `oc-dissect` выводит opcode/длину/состояние
без payload; PCAP и расшифровка TLS вне его задач. Изменения протокола требуют
доказательств и обезличенных тестов. Секреты и приватные журналы не публикуются.
[Лицензия MIT](LICENSE).
