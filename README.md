# API Gateway

[![CI](https://github.com/sarnas-it/api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/sarnas-it/api-gateway/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8.svg)](go.mod)

**Лёгкий API-шлюз на Go со встроенными JWT, RBAC и rate limiting.** Один бинарник
(или образ `scratch`), один YAML-конфиг, никаких плагинов и отдельного
auth-сервиса. Работает в проде на [sarnas.ru](https://sarnas.ru).

English version: [README.en.md](README.en.md)

| Что измерили | `api-gateway` | Nginx / Traefik / Envoy / Kong |
|---|---:|---:|
| Проксирование, c300 | **24 068 req/s** | 24 811 – 27 216 req/s |
| Цена встроенного JWT | **−15.1 %** | Envoy −19.7 %, Kong −28.9 % |
| Внешняя синхронная аутентификация | — | Nginx `auth_request` −89.5 %, Traefik `forwardAuth` −93.8 % |
| Пик памяти, c300 | 121.5 MiB | 15.8 – 314.1 MiB |

Методология, конфиги и скрипты воспроизведения —
[в отчёте о бенчмарке](benchmarks/2026-09-gateway-comparison/README.md).
Числа получены на проксировании мгновенного backend без TLS, разброс между
прогонами около ±10 %: сравнивайте относительные разрывы, не абсолютные значения.

## Запуск за минуту

```bash
# 1. Любой backend на :9000
docker run -d --rm --network host --name echo traefik/whoami --port 9000

# 2. Конфиг: один таргет, один маршрут
cat > config.yaml <<'YAML'
application:
  env: "dev"
server:
  port: 8080
targets:
  - name: "echo"
    url: "http://127.0.0.1:9000"
    timeout: 5s
routing:
  rules:
    - path_prefix: "/"
      target_name: "echo"
jwt:
  secret_key: "change-me-to-a-secure-secret-at-least-256-bits-long"
  required: false   # JWT включается per-route, см. docs/api-gateway-scenarios.md
YAML

# 3. Шлюз
git clone https://github.com/sarnas-it/api-gateway && cd api-gateway
docker build -t api-gateway .
docker run -d --rm --network host --name gw \
  -v $(pwd)/../config.yaml:/etc/proxy/config.yaml:ro \
  api-gateway

curl -i localhost:8080/   # ответ whoami, проксированный шлюзом
```

Разбор запуска, JWT и роли — в
[быстром старте](docs/api-gateway-quickstart.md).

## Когда он подойдёт, а когда нет

Подойдёт, если нужен небольшой шлюз перед несколькими сервисами: JWT и роли на
уровне маршрута, rate limiting, circuit breaker, взвешенная балансировка и
service discovery по labels Docker/Podman.

Не подойдёт, если вам нужен Kubernetes Ingress/Gateway API, плагинная экосистема
уровня Kong или gRPC-специфичные функции. TLS-терминация с автоматическими
сертификатами есть: HTTP-01/TLS-ALPN-01 для точных доменов и DNS-01 (reg.ru)
для wildcard.

## Возможности

- **Маршрутизация по префиксу пути** на несколько бэкенд-сервисов, с поддержкой маршрутизации по `Host` (в т.ч. wildcard-домены `*.example.com`)
- **JWT-аутентификация по маршруту** — часть маршрутов требует токен, часть публична
- **Ролевой доступ** — проверка ролей из claims JWT для конкретного маршрута: `auth.roles` — достаточно любой из перечисленных, `auth.roles_all` — нужны все
- **Rate limiting по маршруту** — token bucket на IP, плюс глобальный лимит
- **Автоматический TLS** — Let's Encrypt через HTTP-01/TLS-ALPN-01 для точных доменов и DNS-01 (reg.ru) для wildcard-сертификатов
- **Health checks и circuit breaker** — автоматическая проверка доступности таргетов, разрыв цепи только на ошибках транспорта
- **Взвешенная балансировка** — таргеты, делящие один роут (`host`, `path_prefix`, `methods`), образуют пул и распределяются weighted round-robin по здоровым кандидатам; в пул входят как статические, так и обнаруженные таргеты
- **CORS** — настраиваемый allowlist источников, отдельное поведение для dev-режима
- **Basic Auth** — с constant-time сравнением хэшей, для служебных путей
- **Проброс claims в заголовки** — маппинг полей JWT в HTTP-заголовки для бэкендов
- **Раздача статики / SPA** — с fallback на `index.html` и поддержкой flat-HTML экспорта (Next.js)
- **Service discovery** — обнаружение бэкендов по labels контейнеров (Docker/Podman), в стиле Traefik
- **Вебхуки/NATS** — публикация событий `on_request`/`on_response`
- **Compile-time модули (`xgate`)** — сборка бинарника с выбранными модулями в духе `xcaddy`: DNS-01 провайдеры, auth-коннекторы, discovery, HTTP-middleware; манифест `xgate.yaml`, lock-файл, `xgate list`
- **Матчеры маршрутов** — `path_regex` (RE2), совпадение по заголовкам и query-параметрам; комбинируются по И
- **Политики балансировки и ретраи** — `round_robin`/`random`/`least_conn`/`ip_hash`/`sticky` (cookie `xg_target` с HMAC-подписью); ретраи идемпотентных методов на транспортных ошибках
- **h2c/gRPC, HTTP/3 и gzip** — cleartext HTTP/2 к бэкендам (`protocol: h2c`), QUIC-листенер для клиентов, сжатие ответов
- **Федерация идентичности** — приём внешних JWT (HS*, RS/ES по удалённому `jwks_url`) с маппингом на внутреннего пользователя
- **Метрики** — `/metrics` (expvar) и `/metrics/prometheus` с гистограммами, allowlist по IP и CIDR
- **Admin API и mTLS** — loopback-статус с атомарным reload; отдельный mTLS-листенер для воркеров (`/api/v1/workers/*`)
- **Graceful shutdown**, структурированное логирование (Zap), трейсинг (OpenTelemetry)

## Документация

- [Быстрый старт](docs/api-gateway-quickstart.md) — минимальный конфиг, запуск локально и в Docker, проверка.
- [Конфигурация](docs/api-gateway-configuration.md) — полный справочник: все секции и поля, значения по умолчанию, примеры.
- [Сценарии](docs/api-gateway-scenarios.md) — типовые задачи: авторизация, RBAC, аудит, права, discovery, балансировка.
- [xgate](docs/xgate.md) — сборка с compile-time модулями; [индекс модулей](docs/modules.md).
- [Дашборд](docs/api-gateway-dashboard.md) — read-only обзор конфигурации, discovery и метрик.

Онлайн-версия с навигацией: [sarnas.ru/docs/api-gateway](https://sarnas.ru/docs/api-gateway).

## Производительность и воспроизводимый бенчмарк

На проксировании «один роут → backend» (proxy-only, 300 соединений) `api-gateway`
показывает **24 068 req/s** — на **11.6 %** ниже Nginx (27 216 req/s) и в пределах
3–5 % от Traefik, Envoy и Kong. Встроенная JWT-аутентификация стоит около **15 %**
пропускной способности, тогда как внешние синхронные схемы Nginx `auth_request` и
Traefik `forwardAuth` — **89–94 %**. Пик памяти под c300 — 121.5 MiB.

Полный отчёт с методологией, таблицами, конфигами и скриптами воспроизведения:
[`benchmarks/2026-09-gateway-comparison/README.md`](benchmarks/2026-09-gateway-comparison/README.md).

## Быстрый старт

```bash
# Скопировать конфиг
cp config.local.example.yaml config.local.yaml
# Отредактировать config.local.yaml — указать свои сервисы и секрет для JWT

# Проверить конфиг, не запуская гейтвей
go run ./cmd/gateway/ -config config.local.yaml -check

# Запуск
go run ./cmd/gateway/ -config config.local.yaml
```

### Сборка с модулями (`xgate`)

`xgate` — compile-time сборщик в духе `xcaddy`: генерирует `main.go` с
blank-импортами выбранных модулей и собирает бинарник.

```bash
go build -o bin/xgate ./cmd/xgate
bin/xgate build --with github.com/acme/gateway-module@v1.0.0 --output bin/api-gateway-custom
```

Подробнее — раздел [«Модули и сборщик xgate»](#модули-и-сборщик-xgate) ниже и
[`docs/xgate.md`](docs/xgate.md).

### Проверка конфигурации

Флаг `-check` загружает и валидирует конфиг, печатает предупреждения и ошибки и завершается с кодом `0` (валиден) или `1` (ошибка). Гейтвей при этом не запускается — удобно для CI и перед деплоем.

```bash
api-gateway -config /etc/proxy/config.yaml -check
# config OK: /etc/proxy/config.yaml
#   targets: 3, routing rules: 8, discovery: true, permissions: false
```

Флаг `-strict` дополнительно считает ошибкой предупреждения о неизвестных ключах:

```bash
api-gateway -config /etc/proxy/config.yaml -check -strict
```

Переменные `${VAR}` в конфиге должны быть определены в окружении: нераскрытая
переменная — ошибка загрузки (fail fast), а не тихий литерал. Неизвестные ключи
YAML не валят запуск, но печатаются предупреждениями (с `-strict` — ошибкой).

В контейнере: `docker run --rm -v ./config.yaml:/etc/proxy/config.yaml ghcr.io/sarnas-it/api-gateway:latest -check`.

## Конфигурация

Полный справочник по всем полям — в [документации](docs/api-gateway-configuration.md); рабочий пример со всеми секциями — в [`config.local.example.yaml`](config.local.example.yaml).

Секции верхнего уровня: `application`, `server`, `compression`, `plugins`,
`http3`, `admin`, `tls`, `static`, `targets`, `jwt`, `basic_auth`, `logging`,
`headers`, `routing`, `permissions`, `webhooks`, `discovery`, `identity`.
Длительности — строки Go duration (`500ms`, `5s`, `5m`).

### Пример маршрутов

| Путь | Таргет | Auth | Роли |
|---|---|---|---|
| `POST /api/v1/auth/login` | auth-api | Нет | — |
| `POST /api/v1/auth/register` | auth-api | Нет | — |
| `POST /api/v1/auth/refresh` | auth-api | Нет | — |
| `/api/v1/auth/*` | auth-api | Да | — |
| `/api/v1/client/*` | client-api | Да | user, admin |
| `/api/v1/admin/*` | admin-api | Да | admin |
| `/api/v1/storage/public/*` | storage-api | Нет | — |
| `/api/v1/storage/*` | storage-api | Да | — |

> Примечание: per-route `rate_limit` применяется к запросу. В более ранних
> сборках из-за ошибки в сопоставлении правила лимит не срабатывал — исправлено.

### mTLS для воркеров (отдельный листенер `:8444`)

Протокол воркеров (`/api/v1/workers/*`) вынесен на отдельный HTTPS-листенер с
обязательным клиентским сертификатом. Основной `:443` не меняется: там
по-прежнему обычная аутентификация по JWT. На worker-листенере доступны только
пути под `/api/v1/workers/`, всё остальное — `404`, даже с валидным клиентским
сертификатом.

```yaml
tls:
  enabled: true
  port: 443
  http_port: 80
  domains:
    - "gw.example.co"
  email: "admin@example.com"
  cache_dir: "/var/lib/api-gateway/certs"
  # Отдельный mTLS-листенер для воркеров; 0 — выключен.
  worker_port: 8444
  # PEM-файл CA (один или несколько сертификатов), которым подписаны
  # клиентские сертификаты воркеров. Обязателен при worker_port > 0.
  worker_client_ca_file: "/etc/api-gateway/worker-ca.pem"
```

Серверный сертификат на `:8444` — тот же, что на `:443` (autocert/certmagic по
`tls.domains`), отдельный сертификат для worker-порта не нужен. Если
`worker_port > 0`, гейтвей при старте читает `worker_client_ca_file`; пустое
значение, нечитаемый файл, отсутствие PEM-сертификатов или конфликт порта с
`port`/`http_port` — ошибка запуска (fail closed). Листенер без проверки клиента
не поднимается.

#### CA и клиентский сертификат для хоста воркеров

Ключ CA держите в секрете (не в git и не на гейтвее). На гейтвей попадает
только публичный `worker-ca.pem`.

```bash
# 1. CA (срок 10 лет)
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout worker-ca.key -out worker-ca.pem \
  -subj "/CN=example-worker-ca"

# 2. Ключ и CSR хоста воркеров (CN — идентификатор хоста)
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout worker.key -out worker.csr \
  -subj "/CN=worker-host-1"

# 3. Подпись CSR нашей CA (срок 1 год)
openssl x509 -req -in worker.csr -CA worker-ca.pem -CAkey worker-ca.key \
  -CAcreateserial -days 365 -sha256 -out worker.crt
```

Воркер ходит строго на `https://gw.example.co:8444` и предъявляет
`worker.crt` + `worker.key`:

```bash
curl --cert worker.crt --key worker.key \
  https://gw.example.co:8444/api/v1/workers/heartbeat
```

Порт `8444` должен быть открыт в firewall, а `gw.example.co` — входить в
`tls.domains` (иначе autocert не выпустит сертификат для SNI).

Без клиентского сертификата (или с сертификатом чужой CA) TLS-handshake
обрывается — HTTP-ответа `404`/`401` в этом случае не будет.

#### Ротация сертификатов

- **Клиентские**: выпустите новый сертификат той же CA и замените его на
  воркере. Перезапуск гейтвея не нужен.
- **Смена CA**: положите в `worker_client_ca_file` новый PEM (можно склеить
  старый и новый CA в одном файле) и перезапустите гейтвей. После перевыпуска
  всех клиентских сертификатов старый CA из файла уберите и перезапустите снова.
- **Проверка перед ротацией**: `curl` с новым сертификатом должен пройти
  TLS-handshake (ошибка `certificate verify failed`/`bad certificate` означает,
  что CA ещё не принят гейтвеем).
- **Серверный** сертификат общий с `:443` и продлевается autocert автоматически.

## JWT-аутентификация, роли и федерация идентичности

Токен принимается из `Authorization: Bearer …` или cookie `cml_access` и
проверяется криптографически на каждом запросе: HMAC (`HS256/384/512`) по
`jwt.secret_key` или RSA/ECDSA/Ed25519 по `jwt.public_key_file`. Опционально
проверяются `exp`, `iss`, `aud`.

Токен можно требовать глобально (`jwt.required`) и на маршруте
(`auth.required`). На маршруте без требования невалидный токен игнорируется —
запрос идёт как анонимный; на требующем — `401`.

Роли читаются из claim `roles` (строка или массив строк): `auth.roles` —
достаточно **любой** из перечисленных, `auth.roles_all` — нужны **все**; если
заданы оба списка, должны выполняться оба условия.

Claims маппятся в заголовки для бэкендов (`jwt.claim_mappings` +
`headers.claim_to_header`), `headers.strip_authorization` и
`auth.strip_token` убирают токен из проксируемого запроса, а
`headers.sign_header` и per-route `sign_v3` добавляют HMAC-подпись
идентичности для внутренних сервисов.

Секция `identity` принимает **внешние** JWT партнёрских провайдеров (свой
`secret_key`/`public_key_file` либо RS/ES по удалённому `jwks_url`) и маппит
их на внутреннего пользователя **только** по `(subject_provider, sub)` через
passport user-lookup с кешем (`identity.user_lookup`). `subject_provider`
обязателен для каждого enabled-провайдера, `subject_claim` по умолчанию `sub`.
Резолва по email нет: claim `email` контролирует подписант токена, и вход по
нему позволил бы выпустить токен с адресом любого активного пользователя.
Если подпись прошла, но субъекта нет, он не замаплен или аккаунт выключен —
отказ (`401`), а не поиск другого способа входа. Дальше такой запрос идёт как
обычный аутентифицированный — с ролями, заголовками и permissions.

## Маршрутизация: матчеры, балансировка, ретраи

Матчеры правила складываются по И: `host` (в т.ч. wildcard `*.example.com`),
`methods`, `headers`, `query` и один из `path_prefix`/`path_regex` (RE2,
компилируется при загрузке конфига — ошибка в выражении роняет старт и
`-check`). Из подходящих правил выигрывает более специфичное: сначала правило
с `host`, затем с бо́льшим числом header/query-матчеров, затем `path_regex`,
затем более длинный `path_prefix`.

Правила с одинаковыми матчерами и разными таргетами образуют пул
балансировки. Политика пула — `lb_policy`: `round_robin` (по умолчанию,
взвешенный), `random`, `least_conn` (по активным запросам к таргету),
`ip_hash` (детерминированно по IP клиента), `sticky` (привязка через cookie
`xg_target` с HMAC-подписью процесса — клиент её не читает и не подделывает).
`retries: 1..5` повторяет идемпотентные методы (GET/HEAD/OPTIONS/TRACE) при
транспортной ошибке.

Для маршрутов с большими телами (WebDAV и подобные) на правиле задаются свои
`max_request_body_size`, `read_timeout`/`write_timeout`, `preserve_host` и
`buffer_request_body: false` (стриминг без обрезания, но аудит-вебхуки такое
тело не увидят) — см.
[пример](docs/api-gateway-configuration.md#маршруты-с-большими-телами-webdav-и-подобные).

## Рейт-лимитинг

Два уровня: per-route `rate_limit` — token bucket на IP клиента (IP берётся из
`X-Forwarded-For` только от доверенных прокси `server.trusted_proxies`, иначе
из `RemoteAddr`), и `routing.global_limit` — один лимит на весь процесс.
Per-route отвечает `429` без `Retry-After`, глобальный — `429` с
`Retry-After: 1`. Лимитеры по IP очищаются после часа простоя.

## CORS

`headers.cors` — allowlist источников: точный origin отражается и получает
`Access-Control-Allow-Credentials`, `*` возвращается без credentials, origin
вне списка CORS-заголовков не получает. Любой `OPTIONS` обрабатывается как
preflight и отвечает `200`. В `application.env: dev` при отсутствии секции
`cors` включается мягкий режим с отражением origin.

## Basic Auth

`basic_auth` защищает служебные пути: constant-time сравнение по SHA-256 от
логина и пароля, исключения — `skip_paths` (точное совпадение или префикс
`путь/`). Стоит во внешнем слое цепочки, поэтому закрывает всё, включая
`/metrics` и статику; после успешной проверки заголовок `Authorization`
удаляется из проксируемого запроса.

## HTTPS и автоматические сертификаты (ACME)

Секция `tls` поднимает HTTPS с сертификатами Let's Encrypt: точные домены
обслуживает autocert (HTTP-01/TLS-ALPN-01), wildcard (`*.example.com`) —
certmagic через DNS-01. DNS-01 провайдеры: встроенный `regru` и libdns-модули,
собранные через `xgate --with` (Cloudflare, deSEC, DigitalOcean, Route53 — см.
«Модули и сборщик xgate»). Запускаются два сервера: HTTPS на `port` и HTTP на
`http_port` для ACME-challenge и редиректа; `staging: true` или свой
`directory_url` — для отладки и других ACME-провайдеров.

Дополнительно: TLS-политика (`min_version`, `cipher_suites`, `curves`), mTLS
на основном листенере (`client_auth` + `client_ca_file`) и отдельный
mTLS-листенер для воркеров (`worker_port` — описан выше в «Конфигурации»).
Полный справочник полей — в
[документации](docs/api-gateway-configuration.md#tls).

## Модули и сборщик xgate

`xgate` — compile-time сборщик в духе `xcaddy`: генерирует `main.go` с
blank-импортами выбранных модулей и собирает бинарник. Рантайм-плагинов нет —
на горячем пути нулевой overhead, а ядро (проксирование, JWT, RBAC,
rate limit, аудит) остаётся встроенным.

```bash
go build -o bin/xgate ./cmd/xgate

bin/xgate build \
  --with code.sarnas.ru/xgate-modules/dns-cloudflare=./modules/dns/cloudflare \
  --output bin/api-gateway-custom
```

`--with module[@version][=replacement]` можно повторять; без версии берётся
latest, `=../path` подставляет локальный форк. Сборка идёт во временном
Go-модуле с `replace` на локальный исходник шлюза — `go.mod` рабочего
репозитория не меняется. Вместо десятка `--with` — манифест `xgate.yaml`
(пример — [`xgate.example.yaml`](xgate.example.yaml)); после сборки рядом
пишется `xgate.lock` с `source_sha`, выбранными модулями и полным
транзитивным графом зависимостей. `xgate list` показывает манифест,
зафиксированные версии и число зависимостей.

### Типы модулей

Модуль — обычный Go-пакет, который регистрируется в `init()` через
`plugin.Register` и реализует один из интерфейсов [`pkg/plugin`](pkg/plugin):

| Тип | Интерфейс | Как включается |
|---|---|---|
| DNS-01 провайдер | `plugin.DNSProvider` | `tls.dns_provider: "<name>"` |
| Auth-коннектор | `plugin.AuthConnector` | `auth.connector: "<name>"` на маршруте |
| Discovery-провайдер | `plugin.DiscoveryProvider` | `discovery.module: "<name>"` |
| HTTP middleware | `plugin.HTTPMiddleware` (`Wrap`) | оборачивает HTTP/HTTPS/HTTP/3 листенеры |

Параметры модуля — секция `plugins.<name>` конфига, читаются в
`Configure(map[string]string)`; неизвестное имя — ошибка запуска. Секции
применяются один раз до старта листенеров: `SIGHUP` их не перечитывает, после
правки `plugins:` нужен рестарт.

Auth-коннектор — единственный аутентификатор своего маршрута (JWT для него не
проверяется): модуль возвращает claims (`id`, опционально `email` и `roles`),
которые дальше идут тем же путём, что и JWT — маппинг в заголовки, роли,
permissions, подпись. Нет identity или ошибка коннектора — `401`.

### Встроенные модули

| Модуль | Тип | Каталог |
|---|---|---|
| Cloudflare | DNS-01 | `modules/dns/cloudflare` |
| deSEC | DNS-01 | `modules/dns/desec` |
| DigitalOcean | DNS-01 | `modules/dns/digitalocean` |
| Route53 | DNS-01 | `modules/dns/route53` |
| Статичные API-ключи | auth-коннектор | `modules/apikey` |
| Файловый discovery | discovery | `modules/file` |
| Шаблон middleware | HTTP middleware | `modules/example` |

Свой модуль: скопируйте `modules/example`, реализуйте нужный интерфейс,
зарегистрируйте в `init()`. Подробно — [`docs/xgate.md`](docs/xgate.md),
индекс модулей — [`docs/modules.md`](docs/modules.md), замысел экосистемы —
[`docs/plugin-ecosystem.md`](docs/plugin-ecosystem.md).

## Протоколы и сжатие

- **h2c/gRPC**: `server.h2c: true` включает cleartext HTTP/2 на клиентском
  листенере, `protocol: h2c` у таргета — HTTP/2 к бэкенду (стриминг и
  trailers передаются; TLS к gRPC-бэкенду пока не поддерживается).
- **HTTP/3 (QUIC)**: `http3.enabled: true` поднимает UDP-листенер на том же
  TLS-конфиге и добавляет `Alt-Svc: h3` в ответы HTTP/1.1/2. Нужен проброс
  UDP и достаточный `net.core.rmem_max`.
- **gzip**: `compression.enabled: true` сжимает ответы для клиентов с
  `Accept-Encoding: gzip` (уровень и `min_size` настраиваются); `Vary:
  Accept-Encoding` добавляется автоматически.

## Статика и SPA

Секция `static` раздаёт файлы до проксирования (но после глобального лимита):
SPA fallback на `index_file` для несуществующих путей, плоские `.html`
(`about.html` для `/about`), `Cache-Control: max-age` из `max_age`. Пути из
`skip_prefixes` уходят в прокси; если маршрут совпал с правилом, у которого
задан `Host`, статика пропускается — host-based роутинг работает и при
смонтированной статике.

## Надёжность: health checks и circuit breaker

`application.health_check: true` включает фоновые проверки таргетов, у которых
задан `health_check` (путь или полный URL); нездоровый таргет исключается из
пула балансировки до восстановления. `application.circuit_breaker: true`
размыкает цепь на ошибках транспорта (502/503/504 дополнительно считаются
сбоем таргета) и проверяет восстановление half-open пробой.

## Permission-сервис

При `permissions.enabled: true` шлюз подмешивает в проксируемый запрос
заголовок с эффективными разрешениями пользователя (`header_name`, по
умолчанию `X-User-Permissions`): из проверенной identity берётся claim `id`,
вызывается `{method} {service_url}{path}` (плейсхолдер `{user_id}`
обязателен), результат кешируется по пользователю на `cache_ttl`. Метод, путь
и заголовок API-ключа (`api_key_header`) настраиваются; по умолчанию —
`GET .../api/v1/users/{user_id}/effective-permissions` с `X-API-Key`.

Любая ошибка permission-сервиса (сеть, таймаут, не-200) не блокирует запрос —
он идёт дальше без заголовка. Кеш сбрасывается через
`POST /_cache/permissions/invalidate` с токеном `X-Invalidate-Token`:
`?user_id=42` — одного пользователя, без параметра — весь кеш. Контракт
сервиса и все поля — в
[справочнике](docs/api-gateway-configuration.md#permissions).

## Вебхуки и аудит

Секция `webhooks` публикует события `on_request`/`on_response` в HTTP-вебхук
или NATS: фильтры по методам, кодам ответа (`on_status_codes`) и
`exclude_paths`; тело запроса (`changes`) и ответа (`response_body`)
включаются опционально — только валидный JSON, ответ до 64 KiB.
HTTP-вебхуки поддерживают батчинг (`batch_size`, `flush_interval`) с
ограниченной очередью и backpressure; `async: true` убирает отправку с
горячего пути запроса. Структура события и примеры — в
[справочнике](docs/api-gateway-configuration.md#webhooks).

## Service discovery (Docker/Podman)

Гейтвей умеет находить бэкенды по labels контейнеров — как Docker-провайдер
Traefik, только без отдельного auth-сервиса и плагинного маркетплейса. Он
подключается к Docker/Podman API через unix socket, находит контейнеры с
маркером `gateway.enable=true`, строит из их labels таргеты и правила роутинга
и применяет их к уже работающему прокси. Обнаруженное **дополняет** статический
конфиг. При конфликте имени таргета побеждает статика (обнаруженный таргет и его
правила отбрасываются). Если обнаруженный сервис регистрирует тот же роут
`(host, path_prefix, methods)`, что и статика, но указывает на другой таргет, он
добавляется в общий пул, а не перекрывается статикой.

Таргет адресуется по имени сервиса (`http://<name>:<port>`), поэтому несколько
реплик одного сервиса раскидывает встроенный DNS Docker/Podman.

Гейтвей балансирует сам: если несколько правил маршрутизации совпадают по
`(host, path_prefix, methods)` и указывают на разные таргеты, они образуют один
пул, и запросы распределяются между здоровыми кандидатами взвешенным
round-robin. В пул входят как статические, так и обнаруженные таргеты — например,
статический `a` и обнаруженный `b` на одном роуте делят нагрузку. Вес задаётся
полем `weight` таргета (по умолчанию `1`); `weight: 0` или отрицательный
исключает таргет из пула.

Несколько реплик **одного** сервиса (одинаковое имя таргета) по-прежнему
раскидывает DNS: discovery дедуплицирует их в один таргет.

### Конфигурация

```yaml
discovery:
  enabled: true
  provider: docker            # docker | podman (один и тот же клиент)
  host: "unix:///var/run/docker.sock"
  api_version: "v1.41"        # "" = запросы без версии
  label_prefix: "gateway"
  service_name_labels:
    - "com.docker.compose.service"
    - "io.podman.compose.service"
  network: ""                 # учитывать только контейнеры этой сети
  debounce: 500ms             # дебаунс событий контейнеров
  resync_interval: 5m         # периодический ре-синк
  default_timeout: 30s
  state_file: /var/lib/api-gateway/discovery-state.json  # фолбэк ("" = выкл.)
```

| поле | по умолчанию | смысл |
|---|---|---|
| `enabled` | `false` | включить discovery |
| `provider` | `docker` | `docker` или `podman` |
| `host` | `unix:///var/run/docker.sock` | socket Docker/Podman API |
| `api_version` | `v1.41` | префикс версии API; `""` — без версии |
| `label_prefix` | `gateway` | префикс labels |
| `service_name_labels` | compose-сервис | цепочка фолбэков имени таргета |
| `network` | `""` | фильтр по сети (пусто — все) |
| `debounce` | `500ms` | задержка перед ре-синком по событиям |
| `resync_interval` | `5m` | период полного ре-синка |
| `default_timeout` | `30s` | таймаут таргета по умолчанию |
| `state_file` | `/var/lib/api-gateway/discovery-state.json` | файл последнего удачного результата (аварийный фолбэк); `""` отключает |

### Аварийный фолбэк

Последний удачный результат discovery сохраняется в `state_file` (атомарная
запись) и применяется при старте гейтвея — поэтому маршруты переживают рестарт,
даже если Docker/Podman недоступен. Для этого каталог `state_file` должен быть
writable (смонтируйте volume). Пустая строка отключает персист.

Ограничение: самый первый холодный старт без файла состояния и с недоступным
Docker/Podman останется без маршрутов, пока провайдер не подключится. Начиная
со второго запуска фолбэк работает.

### Labels

Маркер: `gateway.enable=true` (`true`/`1`/`yes`, регистронезависимо).

Таргет (один на контейнер):

| label | обяз. | смысл | по умолчанию |
|---|---|---|---|
| `gateway.enable` | да | опт-ин контейнера | — |
| `gateway.name` | нет | имя таргета | `service_name_labels`, иначе имя контейнера |
| `gateway.port` | да* | порт | *единственный exposed-порт TCP |
| `gateway.scheme` | нет | `http`/`https` | `http` |
| `gateway.timeout` | нет | таймаут запроса к цели | `discovery.default_timeout` |
| `gateway.health` | нет | health-путь или полный URL | — |
| `gateway.weight` | нет | вес таргета (`0` или отрицательный исключает) | `1` |

Роутеры (0..N на контейнер). Поля задаются коротко (`gateway.<field>` → роутер
`default`) или именованно (`gateway.router.<id>.<field>`):

| поле | смысл | по умолчанию |
|---|---|---|
| `host` | host-правило (wildcard `*.example.com`) | — |
| `path_prefix` | префикс пути | — |
| `methods` | HTTP-методы через запятую | все |
| `strip_path` | срезать префикс при проксировании | `false` |
| `auth.required` | требовать JWT | глобальный `jwt.required` |
| `auth.roles` | роли через запятую: достаточно **любой** из них | — |
| `auth.roles_all` | роли через запятую: нужны **все** | — |
| `auth.strip_token` | удалять `Authorization` | глобальный |
| `rate_limit.rps` | запросов/сек (token bucket) | — |
| `rate_limit.burst` | burst | — |

Роутер без `host` и без `path_prefix` пропускается (нечем матчить).

### Примеры

Один роут (короткая форма):

```yaml
labels:
  gateway.enable: "true"
  gateway.port: "8085"
  gateway.path_prefix: "/api/blog"
```

Несколько роутов с auth и rate-limit (именованная форма):

```yaml
labels:
  gateway.enable: "true"
  gateway.name: "blog"
  gateway.port: "8085"
  gateway.health: "/health"

  gateway.router.public.path_prefix: "/api/blog"
  gateway.router.public.auth.required: "false"

  gateway.router.admin.path_prefix: "/api/admin/blog"
  gateway.router.admin.strip_path: "true"
  gateway.router.admin.methods: "GET,POST"
  gateway.router.admin.auth.required: "true"
  gateway.router.admin.auth.roles: "admin"
  gateway.router.admin.rate_limit.rps: "20"
  gateway.router.admin.rate_limit.burst: "40"
```

Полный пример compose — в [`examples/docker-compose.labels.yml`](examples/docker-compose.labels.yml).
Пошаговый перевод сервиса со статики на labels — в
[`docs/service-discovery-migration.md`](docs/service-discovery-migration.md).

### Podman

Podman отдаёт Docker-совместимый REST API, поэтому используется тот же клиент:

```yaml
discovery:
  provider: podman
  host: "unix:///run/podman/podman.sock"              # rootful
  # host: "unix:///run/user/1000/podman/podman.sock"  # rootless
```

`podman-compose` кладёт имя сервиса в `io.podman.compose.service` — он уже в
`service_name_labels` по умолчанию.

### Безопасность

Socket монтируется **read-only**, клиент делает только `GET` (список контейнеров
и события). Но read-only socket всё равно даёт широкий доступ к Docker daemon;
для чувствительных окружений используйте socket-proxy или удалённый API по TLS.
В labels не храните секреты — они видны через `docker inspect`.

## Docker

```bash
docker build -t api-gateway .
docker run -p 8080:8080 \
  -v $(pwd)/config.local.yaml:/etc/proxy/config.yaml \
  api-gateway
```

## Наблюдаемость: метрики, логи, трейсинг, admin API

`application.metrics_enabled: true` включает метрики и открывает два
эндпоинта: `/metrics` (expvar, для дашборда) и `/metrics/prometheus`
(Prometheus-формат с гистограммой `gateway_request_duration_seconds`,
счётчиками и gauge; лейбл `route` укрупнён, чтобы не раздувать
кардинальность). По умолчанию метрики выключены — сбор добавляет работу на
каждый запрос.

Доступ к обоим ограничивается `application.metrics_allowed_ips` — точные IP и
CIDR-диапазоны (`["10.0.0.5", "172.30.0.0/24"]`); пустой список снимает
ограничение. В TLS-режиме `/metrics` и `/metrics/prometheus` отвечают и на
HTTP-порту для разрешённых IP, чтобы мониторинг мог скрейпить их по внутренней
сети без сертификата; остальные запросы на HTTP-порту уходят в редирект на
HTTPS. Если включён глобальный `basic_auth`, он защищает и метрики — см.
«Панель метрик» в разделе «Дашборд».

Логирование — Zap: `logging.level`, `logging.format` (`json` или `console`;
неверное значение — ошибка запуска), построчный `access_log` выключен по
умолчанию из-за аллокаций на горячем пути. Трейсинг OpenTelemetry включается
переменной окружения `OTEL_EXPORTER_OTLP_ENDPOINT`, pprof — `PPROF_ADDR`.

`admin.enabled: true` поднимает loopback admin API (`127.0.0.1:2019`):
`GET /health`, `GET /status`, `GET /config` (без секретов), `POST /reload` —
атомарно применяет то, что можно менять на лету (`targets`, `routing`,
лимиты, CORS, static, headers…); изменение immutable-полей отклоняется с
`requires restart`, старый конфиг сохраняется. То же перечитывание делает
`SIGHUP`; `SIGINT`/`SIGTERM` — graceful shutdown с таймаутом 30 секунд.

## Дашборд

Отдельный read-only бинарник `cmd/dashboard` показывает сводку конфигурации,
последнее сохранённое состояние service discovery и живые метрики гейтвея.
Гейтвей при этом не изменяется и не требует перезапуска.

```bash
# Сборка и запуск локально
make dashboard
make dashboard-run \
  CONFIG=config.local.yaml \
  DASHBOARD_DISCOVERY_STATE=/var/lib/api-gateway/discovery-state.json
```

Эндпоинты: `GET /` — HTML-обзор, `GET /api/status` — тот же снимок в JSON,
`GET /healthz` — `200 ok`.

### Флаги

| Флаг | По умолчанию | Назначение |
|------|--------------|------------|
| `-config` | `/etc/proxy/config.yaml` | конфиг гейтвея для сводки |
| `-discovery-state` | пусто | файл `discovery.state_file`; пусто — панель выключена |
| `-metrics-url` | `http://127.0.0.1:8080/metrics` | `/metrics` гейтвея; пусто — панель выключена |
| `-listen` | `127.0.0.1:8081` | адрес дашборда |
| `-refresh` | `5s` | интервал авто-обновления HTML |
| `-basic-auth` | пусто | `user:password`; защищает все маршруты |

### Источники данных и деградация

Каждый запрос перечитывает источники заново. Если один из них недоступен
(нет файла, битый JSON, гейтвей не отвечает), страница всё равно отрисовывается
с баннером ошибки, а остальные панели продолжают работать. Дашборд стартует
даже при невалидном конфиге гейтвея.

Секреты (`jwt.secret_key`, `basic_auth.password`, `permissions.api_key`,
`permissions.invalidate_token`) никогда не отображаются; URL с userinfo
редактируются. Учётные данные из URL не попадают и в текст ошибок панели.

### Панель метрик

Панель метрик работает, только если у гейтвея включён
`application.metrics_enabled: true` и `-metrics-url` дашборда указывает на
доступный `/metrics`. Если `metrics_enabled` выключен, `/metrics` не отвечает,
и панель показывает ошибку.

Если у гейтвея включён глобальный `basic_auth`, он защищает и `/metrics`.
Тогда либо добавьте `/metrics` в `basic_auth.skip_paths`, либо разрешите IP
дашборда в `application.metrics_allowed_ips` (можно и то, и другое). Иначе
запрос дашборда получит `401`, и панель покажет ошибку.

```yaml
application:
  metrics_enabled: true
  metrics_allowed_ips: ["10.0.0.5"]   # IP дашборда
basic_auth:
  enabled: true
  username: admin
  password: ${GATEWAY_BASIC_AUTH_PASSWORD}
  skip_paths: ["/health", "/metrics"] # либо пропуск Basic Auth для /metrics
```

По умолчанию дашборд слушает loopback. В контейнере задайте `-listen :8081` и
ограничьте сетевой доступ либо включите `-basic-auth`.

### Docker Compose

Дашборд читает тот же конфиг гейтвея, но **мягко** (`config.LoadLenient`):
переменные `${VAR}` подставляются best-effort, а нераскрытые (или пустые)
остаются литералом `${VAR}` и не считаются ошибкой. Валидация при этом не
запускается, поэтому конфиг без таргетов всё равно отображается. Процессу
дашборда **не нужны переменные окружения гейтвея**.

Нераскрытые литералы `${VAR}` не показываются: секретные поля
(`jwt.secret_key`, `basic_auth.password`, `permissions.api_key`,
`permissions.invalidate_token`) в сводку вообще не копируются, а URL с
userinfo редактируются.

```yaml
services:
  api-gateway:
    image: api-gateway
    volumes:
      - ./config.yaml:/etc/proxy/config.yaml:ro
      - gateway-state:/var/lib/api-gateway

  dashboard:
    build:
      context: .
      dockerfile: Dockerfile.dashboard
    # Переменные окружения гейтвея не требуются: конфиг читается мягко,
    # нераскрытые ${VAR} остаются литералами и не отображаются.
    command:
      - -config=/etc/proxy/config.yaml
      - -discovery-state=/var/lib/api-gateway/discovery-state.json
      - -metrics-url=http://api-gateway:8080/metrics
      - -listen=:8081
      - -basic-auth=admin:${DASHBOARD_PASSWORD}
    ports:
      - "127.0.0.1:8081:8081"
    volumes:
      - ./config.yaml:/etc/proxy/config.yaml:ro
      - gateway-state:/var/lib/api-gateway:ro

volumes:
  gateway-state:
```

Образ собирается отдельно: `docker build -f Dockerfile.dashboard -t api-gateway-dashboard .`

## Разработка

```bash
# Установить зависимости
go mod download

# Запуск с локальным конфигом
go run ./cmd/gateway/ -config config.local.yaml

# Линт
make lint

# Тесты
make test
```

## Лицензия

MIT
