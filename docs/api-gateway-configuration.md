<!-- generated — do not edit here; source: frontend/app/docs/api-gateway/configuration/content.md -->

# Конфигурация

Полный справочник по всем секциям и полям, которые читает код `api-gateway`. Для каждого поля указаны тип, значение по умолчанию, допустимые значения и короткий пример. Значения по умолчанию применяются, когда ключ не задан в YAML; явно заданные значения имеют приоритет.

## Общая структура

Конфиг — один YAML-файл. Путь задаётся флагом `-config` (по умолчанию `/etc/proxy/config.yaml`). Секции верхнего уровня:

| Секция | Назначение |
|---|---|
| `application` | Режим работы, метрики, пул соединений |
| `server` | HTTP-сервер: порт, таймауты, лимит тела |
| `tls` | HTTPS и автоматические сертификаты |
| `static` | Раздача статики и SPA |
| `targets` | Бэкенды |
| `jwt` | Проверка JWT |
| `basic_auth` | Basic Auth на служебные пути |
| `logging` | Уровень, формат, access log |
| `headers` | CORS, проброс claims, подпись, заголовки |
| `routing` | Правила маршрутизации и глобальный лимит |
| `permissions` | Интеграция с permission-сервисом |
| `webhooks` | Публикация событий (webhook/NATS) |
| `discovery` | Обнаружение сервисов по labels |

Длительности записываются строками Go duration: `500ms`, `5s`, `5m`, `1h`.

## Переменные, флаги и сигналы

**Подстановка `${VAR}`.** Перед разбором YAML шлюз раскрывает `${VAR}` и `$VAR` из окружения процесса. Если переменная **не задана или пуста**, шлюз не стартует и возвращает ошибку с именем отсутствующей переменной — молчаливого фолбэка на литерал `${VAR}` нет, чтобы его нельзя было случайно использовать как секрет. Чтобы оставить `${VAR}` в конфиге буквально, экранируйте: `$${VAR}`.

```yaml
jwt:
  secret_key: "${JWT_SECRET}"
permissions:
  service_url: "${PERMISSIONS_URL}"
```

Секреты удобно передавать через `env_file` в docker-compose или переменные окружения контейнера — в самом YAML хранится только ссылка.

**Переменные окружения.** Их читает не конфиг, а сам процесс:

| Переменная | Значение | Смысл |
|---|---|---|
| `PPROF_ADDR` | адрес, напр. `127.0.0.1:6060` | Включает pprof-сервер; пусто — выключен |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | URL, напр. `http://localhost:4318` | Включает OTLP-трейсинг; пусто — выключен |
| `OTEL_EXPORTER_OTLP_INSECURE` | `true` | Отправлять OTLP без TLS |
| `OTEL_INSECURE` | `true` | То же, альтернативное имя |

**Флаги.** `-config <path>` — путь к файлу конфигурации.

**Сигналы.** `SIGHUP` перечитывает конфиг и атомарно применяет изменения, которые можно применить на лету: `targets`, `routing`, rate limits, `server.trusted_proxies`, `server.max_request_body_size`, CORS, static, headers и `tls.redirect_http`. Изменения `server.port`/таймаутов, `tls` (кроме `redirect_http`), `jwt`, `basic_auth`, `identity`, `permissions`, `webhooks`, `metrics` и `logging` требуют рестарта: такой конфиг отклоняется целиком с ошибкой `configuration change requires restart`, старое состояние сохраняется. `SIGINT` и `SIGTERM` запускают graceful shutdown с таймаутом 30 секунд.

**Неизвестные ключи.** Ключи, которых нет в структуре конфига, не считаются ошибкой: шлюз пишет в лог предупреждение `Unknown config key` с точечным путём (например `headers.forward_headers`). Строгий режим намеренно не включён.

## application

Общие настройки процесса.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `env` | string | `""` | `dev` включает мягкий CORS (reflect origin + credentials) и dev-логи. Любое другое значение — обычный режим | `prod` |
| `health_check` | bool | `false` | Включает фоновые health-проверки таргетов, у которых задан `health_check` | `true` |
| `circuit_breaker` | bool | `false` | Включает circuit breaker на ошибках транспорта | `true` |
| `metrics_enabled` | bool | `false` | Собирает метрики и открывает `/metrics` (expvar) и `/metrics/prometheus` | `true` |
| `metrics_allowed_ips` | []string | `[]` (все) | Allowlist клиентских IP для обоих metrics-эндпоинтов | `["10.0.0.5"]` |
| `max_idle_conns_per_host` | int | `1000` | Размер пула keep-alive соединений к каждому таргету. Должен быть не меньше пиковой конкурентности | `1000` |

Метрики выключены по умолчанию, потому что их сбор добавляет работу на каждый запрос. Включайте `metrics_enabled` осознанно; `metrics_allowed_ips` ограничивает доступ к обоим эндпоинтам, если они смотрят наружу.

`/metrics` остаётся в формате `expvar` для дашборда и `monitoring-glue`. `/metrics/prometheus` отдаёт Prometheus-формат с гистограммой `gateway_request_duration_seconds` (лейблы `method`, `route`, `status`), счётчиком `gateway_requests_total`, gauge `gateway_active_requests`/`gateway_target_up` и счётчиком `gateway_rate_limit_denials_total`. Лейбл `route` укрупнён (`/api/blog/posts` → `/api/blog`), чтобы не раздувать кардинальность.

## server

HTTP-сервер.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `port` | int | `8080` | Порт HTTP-сервера (в TLS-режиме не используется) | `8080` |
| `read_timeout` | duration | `5s` | Таймаут чтения запроса | `5s` |
| `write_timeout` | duration | `10s` | Таймаут записи ответа | `30s` |
| `idle_timeout` | duration | `120s` | Таймаут keep-alive соединения | `120s` |
| `max_request_body_size` | int64 (байты) | `10485760` (10 MiB), если ключ не задан | Лимит тела запроса. `0` — **без лимита**, `>0` — лимит в байтах | `1048576` |
| `trusted_proxies` | []string | `[]` | IP/CIDR прокси, которым доверяем `X-Forwarded-For`; пусто — XFF игнорируется | `["173.245.48.0/20", "10.0.0.0/8"]` |
| `h2c` | bool | `false` | Cleartext HTTP/2 на обычном HTTP-листенере (для gRPC-клиентов без TLS) | `true` |

**`trusted_proxies` и клиентский IP.** Если список пуст, клиентский IP берётся из `RemoteAddr`, а `X-Forwarded-For` игнорируется — иначе любой клиент подделает IP и обойдёт rate limit или allowlist `/metrics`. Если запрос пришёл от доверенного прокси, цепочка XFF читается справа налево до первого недоверенного адреса. За Cloudflare перечислите его диапазоны, иначе все клиенты будут выглядеть как один IP.

**Семантика `max_request_body_size`.** Различаются «ключ не задан» и «явный ноль»: не задан — 10 MiB, `0` — без ограничения, положительное число — точный лимит. Тот же лимит применяется к чтению тела для аудита, чтобы вебхуки не вычитывали тело неограниченно.

## compression

Gzip-сжатие ответов. Выключено по умолчанию; включается конфигом.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `enabled` | bool | `false` | Включает gzip для ответов, где клиент прислал `Accept-Encoding: gzip` | `true` |
| `level` | int | `5` | Уровень gzip 1..9 | `5` |
| `min_size` | int | `1024` | Не сжимать ответ с известным `Content-Length` меньше этого значения | `1024` |

Сжатие не применяется к `HEAD`, `101 Upgrade` (WebSocket), `text/event-stream`, уже сжатым ответам (`Content-Encoding` задан) и ответам без сжимаемого `Content-Type`. Заголовок `Vary: Accept-Encoding` добавляется автоматически.

## plugins

Конфигурация compile-time xgate-модулей: имя модуля → параметры.

| Поле | Тип | По умолчанию | Смысл | Пример |
|---|---|---|---|---|
| `<module>` | map[string]string | `{}` | Параметры модуля; читаются его `Configure` | `example: {header: "X-Tenant"}` |

Неизвестное имя модуля или модуль без `Configure` — ошибка запуска. Секции применяются один раз до старта листенеров; SIGHUP их не перечитывает — после правки `plugins:` нужен рестарт процесса.

```yaml
plugins:
  example:
    header: "X-Tenant"
```

## http3

HTTP/3 (QUIC) на том же TLS-конфиге. Требует `tls.enabled: true`.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `enabled` | bool | `false` | Включает UDP/QUIC-листенер | `true` |
| `port` | int | `tls.port` | UDP-порт; обычно тот же 443 | `443` |

В ответах HTTP/1.1/2 добавляется `Alt-Svc: h3=":443"; ma=...`. Для публичного приёма нужен проброс UDP (в Docker — `443:443/udp`), а на хосте — достаточный `net.core.rmem_max` (quic-go рекомендует 7 MiB). Если перед шлюзом стоит Cloudflare, HTTP/3 до клиента терминирует он, и origin-UDP может быть не нужен.

## admin

Loopback admin API для статуса и атомарного reload.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `enabled` | bool | `false` | Включает admin-листенер | `true` |
| `addr` | string | `127.0.0.1:2019` | Адрес; не-loopback требует токен | `127.0.0.1:2019` |
| `token` | string | `""` | Bearer-токен; лучше `${ADMIN_TOKEN}` | `"${ADMIN_TOKEN}"` |

Эндпоинты: `GET /health`, `GET /status` (цели, маршруты, build), `GET /config` (путь, размер, sha256 — без секретов), `POST /reload` (перечитать файл и атомарно применить). Ошибка reload возвращает 400, старый конфиг остаётся. Изменения immutable-полей отклоняются с `requires restart`.

## tls

HTTPS с автоматическими сертификатами Let's Encrypt (ACME).

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `enabled` | bool | `false` | Включает HTTPS-сервер | `true` |
| `port` | int | `443` | HTTPS-порт | `443` |
| `http_port` | int | `80` | HTTP-порт для ACME-challenge и редиректа | `80` |
| `domains` | []string | — | Домены сертификата; обязательны при `enabled: true`. Wildcard (`*.example.com`) — только вместе с `dns_provider` | `["api.example.com", "*.example.com"]` |
| `email` | string | — | Email для регистрации в Let's Encrypt; обязателен | `admin@example.com` |
| `cache_dir` | string | `/var/lib/api-gateway/certs` | Каталог кеша сертификатов; при `staging` используется подкаталог `staging` | `/var/lib/api-gateway/certs` |
| `staging` | bool | `false` | `true` — ACME staging CA (для отладки), `false` — production Let's Encrypt | `false` |
| `directory_url` | string | `""` | Свой ACME directory URL; если задан, перекрывает выбор CA по `staging` | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| `redirect_http` | bool | `false` | Редиректит HTTP на HTTPS; `/health` и `/ready` на HTTP-порту отвечают 200 | `true` |
| `worker_port` | int | `0` | Порт отдельного mTLS-листенера для `/api/v1/workers/*`; `0` — выключен | `8444` |
| `worker_client_ca_file` | string | — | PEM-файл CA (один или несколько сертификатов) для проверки клиентских сертификатов; обязателен при `worker_port > 0` | `/etc/api-gateway/worker-ca.pem` |
| `min_version` | string | `1.2` | Минимальная версия TLS: `1.2` или `1.3` | `1.3` |
| `cipher_suites` | []string | — | TLS 1.0–1.2 cipher suites по именам Go; TLS 1.3 не настраивается | `["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]` |
| `curves` | []string | — | Кривые: `X25519`, `P-256`, `P-384`, `P-521` | `["X25519", "P-256"]` |
| `client_auth` | string | `none` | mTLS на основном листенере: `none`, `request`, `require`, `verify` | `verify` |
| `client_ca_file` | string | — | PEM-файл CA для клиентских сертификатов; обязателен при `client_auth: verify` | `/etc/api-gateway/clients-ca.pem` |
| `dns_provider` | string | `""` | ACME DNS-01 для wildcard: встроенный `regru` или провайдер, собранный через `xgate --with` | `cloudflare` |
| `dns_username` | string | `""` | Логин API reg.ru; секрет лучше подставлять из env | `${REGRU_USER}` |
| `dns_password` | string | `""` | Пароль API reg.ru; секрет лучше подставлять из env | `${REGRU_PASSWORD}` |
| `dns_config` | map[string]string | `{}` | Параметры внешнего libdns-провайдера (например, `api_token`) | `{api_token: "${CF_API_TOKEN}"}` |
| `dns_propagation_timeout` | duration | `2m` | Сколько ждать появления TXT-записи; 0 — дефолт certmagic | `5m` |

При включённом TLS запускаются два сервера: HTTPS на `port` и HTTP на `http_port` для ACME-challenge и редиректа. `staging: true` использует реальный staging CA и отдельный подкаталог кеша, чтобы staging-сертификаты не смешивались с production.

Точные домены обслуживает `autocert` (HTTP-01/TLS-ALPN-01). Wildcard-домены (`*.example.com`) обслуживает `certmagic` через DNS-01: они требуют `dns_provider`. `regru` встроен; остальные провайдеры — libdns-модули, собранные через `xgate --with` (например, `xgate-modules/dns-cloudflare`). Смешивать можно: `["chatcom.online", "*.chatcom.online", "sarnas.ru"]` — wildcard пойдёт через DNS-01, остальные через HTTP-01.

Если задан `worker_port`, поднимается третий листенер — HTTPS с
`ClientAuth: RequireAndVerifyClientCert` и проверкой клиентского сертификата по
CA из `worker_client_ca_file`. Серверный сертификат — тот же, что и на `port`
(autocert для точных доменов, certmagic для wildcard). На этом листенере доступны только пути `/api/v1/workers/*`,
остальные запросы получают `404`. При `worker_port > 0` файл CA обязателен и
читается при старте: ошибка чтения/разбора, отсутствие CA или конфликт
`worker_port` с `port`/`http_port` — ошибка запуска (fail closed).

## static

Раздача статики и SPA-приложений. Обрабатывается до проксирования, но после глобального лимита.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `apps` | []object | `[]` | Список SPA/статических приложений | см. ниже |
| `skip_prefixes` | []string | `[]` | Пути, которые не отдаются статикой (уходят в прокси) | `["/api"]` |

Поля элемента `apps`:

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `path_prefix` | string | — | URL-префикс приложения | `/` |
| `root_dir` | string | — | Каталог со статикой | `/app/static` |
| `index_file` | string | `index.html` | Fallback-файл SPA | `index.html` |
| `max_age` | int (сек) | `3600` | Значение `Cache-Control: max-age` | `3600` |

```yaml
static:
  skip_prefixes: ["/api"]
  apps:
    - path_prefix: "/"
      root_dir: "/app/static"
      index_file: "index.html"
      max_age: 3600
```

Если маршрут совпадает с правилом, у которого задан `Host`, статика пропускается — так host-based роутинг работает при смонтированной статике. Для несуществующих путей отдаётся `index_file` (SPA fallback); поддерживаются и плоские `.html`-файлы (`about.html` для `/about`).

## targets

Список бэкендов. Имя и URL обязательны; имена уникальны.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `name` | string | — | Уникальное имя таргета | `api` |
| `url` | string | — | Базовый URL бэкенда | `http://127.0.0.1:9001` |
| `timeout` | duration | `30s` | Таймаут запроса к таргету | `10s` |
| `path_prefix` | string | `""` | Префикс; при пустых `routing.rules` из него создаётся правило | `/api` |
| `strip_prefix` | bool | `false` | Удалять префикс при проксировании | `false` |
| `weight` | int | `1`, если ключ не задан | Вес в пуле маршрута: `nil` — 1, `0` и отрицательные исключают таргет, `>0` — вес | `2` |
| `health_check` | string | `""` | URL health-проверки; работает при `application.health_check: true` | `http://127.0.0.1:9001/health` |
| `tls` | object | нет | TLS к HTTPS-бэкенду (только для `https://` URL) | см. ниже |
| `tls.ca_file` | string | `""` | PEM-файл CA для проверки сертификата бэкенда | `/etc/api-gateway/backend-ca.pem` |
| `tls.server_name` | string | `""` | SNI/имя для проверки сертификата | `internal.example` |
| `tls.insecure_skip_verify` | bool | `false` | Не проверять сертификат; взаимоисключающе с `ca_file` | `false` |
| `tls.cert_file` / `tls.key_file` | string | `""` | Клиентский сертификат для mTLS к бэкенду; задаются парой | `/etc/api-gateway/client.pem` |
| `protocol` | string | `""` | Протокол к бэкенду: пусто (HTTP/1.1) или `h2c` (cleartext HTTP/2, в т.ч. gRPC) | `h2c` |
| `rest` | object | нет | «Отдых» таргета в пуле при ответах 429/503; по умолчанию выключен | см. ниже |
| `rest.enabled` | bool | `false` | Включает отдых таргета | `true` |
| `rest.base` | duration | `1m` | Пауза при 429/503 без `Retry-After`; удваивается при повторах | `30s` |
| `rest.max` | duration | `30m` | Потолок паузы и окно сброса счёта эскалации | `15m` |

**h2c и gRPC.** Для gRPC клиентский листенер включает `server.h2c: true`; таргет получает `protocol: h2c` и `http://` URL. Прокси передаёт HTTP/2-поток, trailers и стриминг; TLS к gRPC-бэкенду пока не поддерживается (h2c только cleartext).

**Семантика `weight`.** Таргеты, чьи правила совпадают по `(host, path_prefix, methods)`, образуют один пул и распределяются взвешенным round-robin по здоровым кандидатам. Отсутствие ключа `weight` — это вес 1, а явный `weight: 0` (или отрицательный) **исключает** таргет из выбора. Различайте эти два случая.

**Отдых таргета (`rest`).** Опциональная мягкая пауза в пуле при ответах `429` и `503` (идея magpie, issue #52). Ответ с заголовком `Retry-After` (секунды или HTTP-дата) выводит таргет из выбора ровно на указанное время, но не дольше `rest.max`. Без заголовка пауза начинается с `rest.base` и удваивается при повторах подряд до потолка `rest.max`; если с прошлого отдыха прошло больше `max`, счёт начинается заново с `base`. Отдых не трогает circuit breaker и health check — таргет остаётся «здоровым», пул его просто пропускает (включая sticky-привязку). Если отдыхают все кандидаты, запрос идёт тому, кто вернётся раньше всех, а не падает с 503; одиночный таргет маршрута обслуживает запросы всегда. Причина и момент возврата видны в метриках (`gateway_target_rest_until`, `gateway_target_rest_reason`; Prometheus — `gateway_target_rest_until_seconds`) и на дашборде.

```yaml
targets:
  - name: "llm-a"
    url: "http://llm-a:9001"
    rest:
      enabled: true
      base: 1m
      max: 30m
```

## jwt

Проверка JWT. Токен берётся из `Authorization: Bearer …` или из cookie `cml_access`.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `secret_key` | string | `""` | Симметричный ключ для HMAC | `"${JWT_SECRET}"` |
| `public_key_file` | string | `""` | PEM-файл публичного ключа для RSA/ECDSA/Ed25519 | `/etc/proxy/public.pem` |
| `algorithm` | string | `HS256` | `HS256/384/512`, `RS256/384/512`, `ES256/384/512`, `EdDSA`/`ED25519` | `RS256` |
| `validate_exp` | bool | `false` | Проверять срок действия; принудительно `true`, если `required: true` | `true` |
| `validate_iss` | bool | `false` | Проверять issuer | `false` |
| `expected_iss` | string | `""` | Ожидаемый issuer | `"https://auth.example"` |
| `validate_aud` | bool | `false` | Проверять audience | `false` |
| `expected_aud` | string | `""` | Ожидаемый audience | `"api"` |
| `claim_mappings` | []string | `["sub"]` | Claims, извлекаемые в контекст; при пустом значении дополнительно маппится `sub → X-User-ID` | `["id", "email", "roles"]` |
| `required` | bool | `false` | Требовать токен глобально | `false` |

Глобальный `required` перекрывается настройкой маршрута `auth.required`. Предъявленный токен всегда проверяется криптографически: на маршруте без требования невалидный токен игнорируется (запрос идёт как анонимный), на требующем — возвращается 401.

## basic_auth

Basic Auth для служебных путей. Проверка — constant-time по SHA-256 от логина и пароля.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `enabled` | bool | `false` | Включает Basic Auth | `true` |
| `username` | string | `""` | Логин | `internal` |
| `password` | string | `""` | Пароль | `"${BASIC_PASS}"` |
| `skip_paths` | []string | `[]` | Пути без Basic Auth; совпадение точное или по префиксу `путь/` | `["/health"]` |

Basic Auth стоит во внешнем слое цепочки и защищает всё, включая `/metrics` и статику, кроме `skip_paths`. При успехе заголовок `Authorization` удаляется перед проксированием.

## logging

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `level` | string | `info` | `debug`, `info`, `warn`, `error`, `panic`, `fatal` | `debug` |
| `format` | string | `text` | `console`, `text` (алиас `console`), `json`; регистр не важен. Иное значение — ошибка запуска | `json` |
| `access_log` | bool | `false` | Построчный лог каждого запроса; выключен по умолчанию из-за аллокаций | `true` |

Неверный `format` не «молча» превращается в консоль: загрузка конфига завершается ошибкой `logging.format must be one of console, text, json`.

## headers

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `strip_authorization` | bool | `false` | Удалять `Authorization` перед проксированием | `true` |
| `claim_to_header` | map[string]string | `{}` | Claim → имя заголовка; при пустых `claim_mappings` по умолчанию `sub → X-User-ID` | `{id: X-User-ID}` |
| `add_headers` | map[string]string | `{}` | Заголовки, добавляемые в каждый проксируемый запрос | `{X-Gateway: sarnas}` |
| `sign_header` | string | `""` | Имя заголовка для HMAC-SHA256(id, `permissions.api_key`) в hex | `X-User-Signature` |
| `cors` | object | нет | Настройки CORS (см. ниже) | см. ниже |

Поля `cors`:

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `enabled` | bool | `false` | Включает CORS | `true` |
| `allowed_origins` | []string | `[]` | `*` или точные origin; при `*` credentials не выставляются | `["https://app.example"]` |
| `allowed_methods` | []string | встроенный список | Разрешённые методы | `["GET", "POST"]` |
| `allowed_headers` | []string | встроенный список | Разрешённые заголовки | `["Authorization"]` |
| `expose_headers` | []string | встроенный список | Заголовки, видимые браузеру | `["X-Request-ID"]` |
| `max_age` | int (сек) | `86400` | Время кеширования preflight | `86400` |

```yaml
headers:
  strip_authorization: true
  claim_to_header:
    id: "X-User-ID"
    roles: "X-User-Roles"
  add_headers:
    X-Gateway-Version: "1.0.0"
  sign_header: "X-User-Signature"
  cors:
    enabled: true
    allowed_origins: ["https://app.example"]
    max_age: 86400
```

Правила CORS: при точном совпадении origin он отражается и выставляется `Access-Control-Allow-Credentials`; при `*` возвращается `*` без credentials; не попавший в allowlist origin CORS-заголовков не получает. Любой `OPTIONS` обрабатывается как preflight и возвращает 200. В `env: "dev"` при отсутствии секции `cors` включается мягкий режим с отражением origin.

`sign_header` вычисляется только если заданы и `sign_header`, и `permissions.api_key`, и в токене есть claim `id`.

## routing

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `rules` | []object | `[]` | Правила маршрутизации; при пустом списке генерируются из `targets` с `path_prefix` | см. ниже |
| `global_limit` | object | нет | Глобальный лимит на весь процесс | см. ниже |

Поля правила `rules[]`:

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `host` | string | `""` | Матч по `Host`; поддерживается wildcard `*.example.com` | `api.example.com` |
| `path_prefix` | string | — | Префикс пути; обязателен, если не задан `path_regex` | `/api` |
| `path_regex` | string | `""` | RE2-регулярка по пути (`MatchString`, без автoякорей); взаимоисключающе с `path_prefix` | `^/api/v[0-9]+/` |
| `headers` | map | `{}` | Все заголовки должны совпасть; пустое значение — «заголовок присутствует» | `{X-Tenant: "b"}` |
| `query` | map | `{}` | Все query-параметры должны совпасть; пустое значение — «параметр присутствует» | `{debug: "1"}` |
| `target_name` | string | — | Имя таргета; обязателен и должен существовать | `api` |
| `methods` | []string | все | Фильтр HTTP-методов (регистр не важен) | `["GET", "POST"]` |
| `strip_path` | bool | `false` | Удалять префикс при проксировании | `true` |
| `lb_policy` | string | `round_robin` | Политика пула: `round_robin`, `random`, `least_conn`, `ip_hash`, `sticky` | `least_conn` |
| `retries` | int | `0` | Повторы при транспортной ошибке для GET/HEAD/OPTIONS/TRACE, 0..5 | `1` |
| `auth` | object | нет | Аутентификация маршрута | см. ниже |
| `rate_limit` | object | нет | Лимит маршрута | см. ниже |
| `sign_v3` | object | нет | Per-route HMAC v3 подпись запроса (`X-Service-ID`/`X-Key-ID`/`X-User-Timestamp`/`X-User-Signature`) для бэкендов на go-hmac-auth | см. ниже |
| `sign_v2` | bool | `false` | Per-route HMAC v2 подпись (мониторинг); секрет — `permissions.api_key`, несовместима с `sign_v3` | `true` |
| `max_request_body_size` | int | лимит сервера | Лимит тела запроса для маршрута, байты; `0` — без лимита | `536870912` |
| `read_timeout` | duration | `server.read_timeout` | Дедлайн чтения запроса для маршрута (`http.ResponseController`) | `15m` |
| `write_timeout` | duration | `server.write_timeout` | Дедлайн записи ответа для маршрута | `1h` |
| `preserve_host` | bool | `false` | Передавать бэкенду исходный `Host` (по умолчанию — host таргета) | `true` |
| `buffer_request_body` | bool | `true` | Читать тело в память (нужно аудит-вебхукам). `false` — стриминг без обрезания | `false` |

Матчеры правила складываются по И: `host`, `methods`, `headers`, `query` и один из `path_prefix`/`path_regex`. Если подходят несколько правил, выигрывает более специфичное: сначала правило с `host`, затем с бо́льшим числом header/query-матчеров, затем `path_regex`, затем более длинный `path_prefix`. Регулярка компилируется при загрузке конфига: ошибка в выражении роняет старт и `gateway --check`.

Правила, различающиеся матчерами, образуют разные пулы балансировки; в один пул попадают только правила с одинаковыми `(host, path_prefix, path_regex, methods, headers, query)`.

`lb_policy` действует на пул правил с одинаковыми `(host, path_prefix, methods)`. `least_conn` учитывает активные запросы к таргету, `ip_hash` детерминированно выбирает по IP клиента. `retries` повторяет только методы без тела (GET/HEAD/OPTIONS/TRACE) при транспортной ошибке; 502/503/504 дополнительно считаются сбоем таргета для circuit breaker.

`sticky` привязывает клиента к таргету через cookie `xg_target`: значение — имя таргета под HMAC-подписью процесса (имя не читается клиентом, подделать нельзя). Cookie ставится на первом выборе и обновляется, только если привязка недействительна: таргет убран из пула, нездоров, подпись неверна. Ключ живёт в памяти: после рестарта шлюза клиенты один раз перепривязываются. Атрибуты: `Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure` при TLS.

`auth`: `required` (bool, по умолчанию наследует глобальный `jwt.required`; непустые `roles`/`roles_all` сами требуют токен, даже если глобальный `required: false`), `roles` ([]string, достаточно **любой** из перечисленных ролей), `roles_all` ([]string, должны присутствовать **все** перечисленные роли), `strip_token` (bool, наследует `headers.strip_authorization`), `connector` (string, имя compile-time xgate-модуля `plugin.AuthConnector`).

`connector` — единственный аутентификатор маршрута: JWT для него не проверяется, credentials проверяет модуль (API-ключ, introspection и т.п.). Отсутствие identity или ошибка коннектора — 401, `required: false` этого не отключает. Identity раскладывается в заголовки тем же путём, что и JWT (`claim_mappings`, `headers.claim_to_header`, `permissions`, per-route `sign_v3`), роли проверяются так же. Имя коннектора должно быть вкомпилировано, иначе `--check` и старт завершаются ошибкой.

`roles` и `roles_all` читают claim `roles` токена (строка или массив строк). Если заданы оба списка, роль должна пройти оба условия: `(любая из roles) И (все из roles_all)`. Если claim `roles` отсутствует или его тип не строка и не массив строк, маршрут с требованиями ролей отвечает 401.

```yaml
auth:
  required: true
  roles: ["admin", "support"]   # достаточно любой из двух
  roles_all: ["staff", "mfa"]   # и при этом обязательны обе
```

Маршрут с внешним коннектором:

```yaml
routing:
  rules:
    - path_prefix: "/api/keys"
      target_name: "api"
      auth:
        connector: "apikey"     # модуль, собранный через xgate
        roles: ["admin"]
```

`sign_v2: true` подписывает запрос по контракту мониторинга: `HMAC-SHA256(permissions.api_key, userID + "\n" + METHOD + "\n" + path + "\n" + timestamp)` в hex, заголовки `X-User-ID`/`X-User-Timestamp`/`X-User-Signature`. Метод приводится к верхнему регистру. Требует непустой `permissions.api_key` и несовместима с `sign_v3` — обе ошибки ловятся на `--check` и старте. Подпись считается по пути до `strip_path`, поэтому на sign_v2-маршруте префикс обрезать нельзя: бэкенд проверяет подпись по тому пути, который видит.

`rate_limit`: `requests_per_second` (float, token bucket), `burst` (int). `global_limit` имеет те же поля, но применяется ко всем запросам процесса, а не на IP.

```yaml
routing:
  global_limit:
    requests_per_second: 1000
    burst: 2000
  rules:
    - path_prefix: "/api"
      target_name: "api"
      strip_path: true
      auth:
        required: true
        roles: ["user"]
      rate_limit:
        requests_per_second: 50
        burst: 100
```

### Маршруты с большими телами (WebDAV и подобные)

Общий `server.max_request_body_size` (10 МиБ) и `server.read_timeout` рассчитаны
на JSON-API. Для протоколов, которые льют файлы, лимиты задаются на маршруте;
тело при этом нельзя буферизовать (аудит-вебхуки его не увидят):

```yaml
targets:
  - name: dav
    url: "http://workspace-storage:8091"
    timeout: 1h
routing:
  rules:
    - host: "dav.example.com"
      path_prefix: "/dav/"
      target_name: "dav"
      preserve_host: true          # WebDAV Destination в MOVE/COPY
      buffer_request_body: false   # стриминг, без обрезания
      max_request_body_size: 536870912
      read_timeout: 15m
      write_timeout: 1h
```

`methods` не задан — маршрут принимает любой метод, включая `PROPFIND`,
`PROPPATCH`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`. При превышении лимита
клиент получает `413`, а не усечённый файл в бэкенде.

Выбирается правило с самым длинным совпадающим `path_prefix` среди тех, у кого совпали `host` и `methods`. Если ничего не совпало — 404. Правила, совпадающие по `(host, path_prefix, methods)`, делят один пул балансировки и **обязаны** совпадать по `auth`, `strip_path` и `rate_limit`, иначе запуск завершается ошибкой.

## permissions

Интеграция с внешним permission-сервисом: шлюз подмешивает в проксируемый запрос заголовок с эффективными разрешениями пользователя. Модуль включается `permissions.enabled: true`; при этом `service_url` обязателен, иначе загрузка конфига завершается ошибкой `permissions.service_url is required when permissions.enabled is true`.

### Как это работает

```
JWT (Authorization: Bearer / cookie cml_access)
        │
        ▼
проверка подписи и claims
        │  claim id из jwt.claim_mappings
        ▼
   toInt(id) ── нет claim / не приводится к int ──► заголовок не выставляется,
        │                                            запрос идёт дальше (не 401)
        │ ok
        ▼
   кеш по user_id ── hit ────────────────────────────┐
        │ miss                                        │
        ▼                                             │
{method} {service_url}{path}  ({user_id} подставляется)
        │                                             │
        ├─ 200: кешируем, берём permissions ──────────┘
        └─ иное: ошибка, заголовок не выставляется, запрос идёт дальше
        │
        ▼
X-User-Permissions: "orders:read,orders:write"   (только если список непуст)
```

1. После криптографической проверки токена шлюз берёт из него claim `id`. Claim должен быть перечислен в `jwt.claim_mappings` (например `["id", "email", "roles"]`), иначе он не попадёт в извлечённый набор и заголовок не выставится.
2. Значение `id` приводится к `int`: принимаются JSON-число (`float64`), `int` и числовая строка. Если claim отсутствует или не приводится — заголовок не выставляется, запрос продолжается без 401.
3. При успешном приведении шлюз смотрит кеш по `user_id`. При промахе вызывается permission-сервис (см. контракт ниже), результат кладётся в кеш.
4. Если список `permissions` непуст, выставляется заголовок `header_name` со значениями, склеенными через запятую. Пустой список заголовок не выставляет.
5. Любая ошибка (сеть, таймаут, не-200, ошибка декодирования) логируется как `failed to set permissions header`; запрос всё равно проксируется без заголовка.

Блок выполняется только при предъявленном токене, прошедшем проверку, — на анонимных запросах заголовок не появляется.

### Контракт permission-сервиса

Шлюз вызывает один эндпоинт, собранный из `method`, `service_url` и `path`:

```
{method} {service_url}{path}
{api_key_header}: {api_key}        # только если api_key задан
```

- `{method}` — `permissions.method` (по умолчанию `GET`).
- `{path}` — `permissions.path` (по умолчанию `/api/v1/users/{user_id}/effective-permissions`); подстрока `{user_id}` заменяется на целое число, полученное из claim `id`. Плейсхолдер `{user_id}` обязателен, иначе загрузка конфига завершается ошибкой.
- `{api_key_header}` — `permissions.api_key_header` (по умолчанию `X-API-Key`); заголовок добавляется, только если `api_key` непустой.
- Таймаут HTTP-клиента — 5 секунд.

Если `method`, `path` и `api_key_header` не заданы, поведение прежнее: `GET {service_url}/api/v1/users/{user_id}/effective-permissions` с заголовком `X-API-Key`. Существующему permission-сервису менять ничего не нужно — достаточно не добавлять новые поля.

Успешный ответ — HTTP 200 с JSON-объектом:

```json
{
  "user_id": 42,
  "permissions": ["orders:read", "orders:write", "reports:view"],
  "inherited_from_role": ["orders:read", "reports:view"],
  "direct_allowed": ["orders:write"],
  "direct_denied": ["admin:all"]
}
```

| Поле | Тип | Обязательно | Смысл |
|---|---|---|---|
| `user_id` | int | нет | Идентификатор пользователя |
| `permissions` | []string | да | Итоговый список эффективных разрешений; **единственное поле, которое использует шлюз** |
| `inherited_from_role` | []string | нет | Разрешения, унаследованные от роли |
| `direct_allowed` | []string | нет | Разрешения, выданные пользователю напрямую |
| `direct_denied` | []string | нет | Явно запрещённые разрешения |

Шлюз читает только `permissions`, остальные поля можно не возвращать. Любой не-200 (включая 401/403/404/5xx) считается ошибкой: заголовок не выставляется, запрос продолжается. Тело ответа должно быть валидным JSON.

### Кеш и инвалидация

- Эффективные разрешения кешируются по `user_id` на `cache_ttl` (по умолчанию `300s`). После прогрева на одного пользователя приходится один вызов сервиса за TTL.
- Чтобы изменения прав не «залипали» до истечения TTL, permission-сервис (или оператор) вызывает инвалидацию:

```
POST /_cache/permissions/invalidate
X-Invalidate-Token: {invalidate_token}
```

- `?user_id=42` сбрасывает запись одного пользователя; без параметра — весь кеш.
- Неверный или отсутствующий `X-Invalidate-Token` — 401; нечисловой `user_id` — 400.
- Эндпоинт доступен, только когда модуль включён, и обрабатывается во внешнем слое цепочки — до Basic Auth, поэтому `basic_auth` его не защищает. Доступ ограничен только `X-Invalidate-Token`.
- Модуль стоит на горячем пути, поэтому сервис должен отвечать быстро: кеш сводит нагрузку к одному вызову на пользователя за TTL.

### Поля конфигурации

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `enabled` | bool | `false` | Включает модуль | `true` |
| `service_url` | string | — | Базовый URL permission-сервиса; обязателен при `enabled` | `http://permissions:8080` |
| `method` | string | `GET` | HTTP-метод запроса к permission-сервису | `POST` |
| `path` | string | `/api/v1/users/{user_id}/effective-permissions` | Шаблон пути; `{user_id}` заменяется на идентификатор пользователя. Плейсхолдер `{user_id}` обязателен | `/v2/users/{user_id}/permissions` |
| `api_key_header` | string | `X-API-Key` | Заголовок, в который кладётся `api_key`, если он задан | `Authorization` |
| `cache_ttl` | duration | `300s` | TTL кеша разрешений по пользователю | `300s` |
| `header_name` | string | `X-User-Permissions` | Заголовок с разрешениями (через запятую) | `X-User-Permissions` |
| `invalidate_token` | string | значение `api_key` | Токен для инвалидации кеша; если пуст — равен `api_key` | `"${INVALIDATE_TOKEN}"` |
| `api_key` | string | `""` | API-ключ сервиса (отправляется в `api_key_header`); также секрет для `headers.sign_header` | `"${PERMISSIONS_KEY}"` |

### Пример конфигурации

```yaml
jwt:
  secret_key: "${JWT_SECRET}"
  claim_mappings: ["id", "email", "roles"]

permissions:
  enabled: true
  service_url: "http://permissions:8080"
  cache_ttl: 300s
  header_name: "X-User-Permissions"
  api_key: "${PERMISSIONS_KEY}"
  invalidate_token: "${INVALIDATE_TOKEN}"
```

Кастомный эндпоинт — другой метод, путь и заголовок ключа:

```yaml
permissions:
  enabled: true
  service_url: "http://permissions:8080"
  method: "POST"
  path: "/v2/users/{user_id}/permissions"
  api_key_header: "Authorization"
  api_key: "${PERMISSIONS_KEY}"
```

## webhooks

Публикация событий на каждый запрос или ответ. Транспорты — HTTP webhook и NATS.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `name` | string | — | Уникальное имя вебхука | `audit` |
| `transport` | string | — | `webhook` или `nats` | `webhook` |
| `webhook_url` | string | `""` | URL приёмника; обязателен для `webhook` | `https://audit.example/events` |
| `nats_url` | string | `""` | URL NATS; обязателен для `nats` | `nats://nats:4222` |
| `subject` | string | `""` | NATS subject; обязателен для `nats` | `audit.events` |
| `trigger` | string | — | `on_request` или `on_response` | `on_response` |
| `methods` | []string | все | Фильтр методов (регистр не важен) | `["POST", "PUT", "PATCH", "DELETE"]` |
| `on_status_codes` | []int | все | Для `on_response`: публиковать только эти коды | `[200, 201]` |
| `exclude_paths` | []string | `[]` | Префиксы путей, исключённые из публикации | `["/health"]` |
| `async` | bool | `false` | Отправлять в горутине, не блокируя запрос | `true` |
| `include_request_body` | bool | `true`, если ключ не задан | Публиковать тело запроса как `changes` (только JSON) | `false` |
| `include_response_body` | bool | `false` | Публиковать тело ответа как `response_body` (только JSON, до 64 KiB) | `true` |
| `batch_size` | int | `0`/`1` | `>1` включает батчинг HTTP-вебхука | `1000` |
| `flush_interval` | duration | `200ms` | Максимальная задержка перед отправкой неполной пачки | `100ms` |

### Структура события

Тело события (одно событие, а также элемент массива `events` в пачке):

| Поле | Тип | Всегда | Смысл |
|---|---|---|---|
| `method` | string | да | HTTP-метод запроса |
| `path` | string | да | Путь запроса |
| `query` | string | нет | Строка запроса без `?` |
| `user_id` | string | нет | Из заголовка `X-User-ID` (заполняется маппингом claims) |
| `user_email` | string | нет | Из заголовка `X-User-Email` |
| `user_roles` | string | нет | Из заголовка `X-User-Roles` (роли через запятую) |
| `request_id` | string | да | `X-Request-ID` запроса |
| `status_code` | int | для `on_response` | Код ответа |
| `timestamp` | string (RFC3339) | да | Время события |
| `changes` | object | нет | Тело запроса как JSON (если `include_request_body`, по умолчанию включено) |
| `response_body` | object | нет | Тело ответа как JSON, до 64 KiB (если `include_response_body`) |

Поля с `omitempty` (всё, кроме `method`, `path`, `request_id`, `timestamp`) отсутствуют в JSON, если пусты. `headers` зарезервировано и сейчас не заполняется. `changes` и `response_body` попадают в событие, только если тело — валидный непустой JSON-объект (для `response_body` ещё и `Content-Type: application/json`).

Пример одного события (HTTP-вебхук без батчинга или сообщение NATS):

```json
{
  "method": "POST",
  "path": "/api/v1/admin/users",
  "user_id": "42",
  "user_email": "admin@example.com",
  "user_roles": "admin",
  "request_id": "9f2c1e7a4b3d5c60",
  "status_code": 201,
  "timestamp": "2026-09-13T12:34:56.789Z",
  "changes": { "email": "new@example.com", "role": "editor" }
}
```

Батчинг (`batch_size > 1`) шлёт один POST с телом:

```json
{
  "count": 2,
  "events": [
    { "method": "POST", "path": "/api/v1/admin/users", "request_id": "…", "status_code": 201, "timestamp": "2026-09-13T12:34:56.789Z", "changes": { "role": "editor" } },
    { "method": "GET", "path": "/api/v1/admin/users/42", "request_id": "…", "status_code": 200, "timestamp": "2026-09-13T12:34:56.812Z" }
  ]
}
```

Очередь батчера ограничена (8192 события); при переполнении постановка блокируется — события не теряются, но запросы замедляются (backpressure). Батчинг применяется только к HTTP-вебхукам; NATS шлёт по одному событию. Соединение NATS устанавливается по `nats_url` **первого** вебхука, поэтому у всех NATS-вебхуков URL должен совпадать.

### Примеры

Аудит изменений (только мутации, с телом запроса):

```yaml
webhooks:
  - name: audit-mutations
    transport: webhook
    webhook_url: "https://audit.example/events"
    trigger: on_response
    methods: ["POST", "PUT", "PATCH", "DELETE"]
    include_request_body: true
    batch_size: 1000
    flush_interval: 100ms
    async: true
```

Аудит чтений и записей по админским путям (тело ответа включено):

```yaml
webhooks:
  - name: audit-admin
    transport: webhook
    webhook_url: "https://audit.example/admin"
    trigger: on_response
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
    include_response_body: true
    exclude_paths: ["/health", "/metrics"]
    async: true
```

Публикация в NATS:

```yaml
webhooks:
  - name: audit-nats
    transport: nats
    nats_url: "nats://nats:4222"
    subject: "audit.events"
    trigger: on_response
    methods: ["POST", "PUT", "PATCH", "DELETE"]
    async: true
```

## discovery

Обнаружение бэкендов по labels контейнеров Docker/Podman. Обнаруженные таргеты и правила **дополняют** статические; при конфликте имени таргета побеждает статика. Если обнаруженный сервис описывает тот же маршрут `(host, path_prefix, methods)`, он попадает в общий пул с статикой.

| Поле | Тип | По умолчанию | Смысл и значения | Пример |
|---|---|---|---|---|
| `enabled` | bool | `false` | Включает discovery | `true` |
| `provider` | string | `docker` | `docker` или `podman` (один клиент) | `docker` |
| `module` | string | `""` | Имя compile-time xgate-модуля `plugin.DiscoveryProvider`; если задан, встроенный Docker-провайдер не используется | `file` |
| `host` | string | `unix:///var/run/docker.sock` | Socket Docker/Podman API | `unix:///var/run/docker.sock` |
| `api_version` | string | `v1.41` | Версия API; `""` — запросы без версии | `v1.41` |
| `label_prefix` | string | `gateway` | Префикс labels | `gateway` |
| `service_name_labels` | []string | compose-сервис Docker и Podman | Цепочка фолбэков имени таргета | `["com.docker.compose.service"]` |
| `network` | string | `""` | Учитывать только контейнеры этой сети; пусто — все | `proxy` |
| `debounce` | duration | `500ms` | Задержка перед ре-синком по событиям | `500ms` |
| `resync_interval` | duration | `5m` | Период полного ре-синка | `5m` |
| `default_timeout` | duration | `30s` | Таймаут обнаруженного таргета по умолчанию | `30s` |
| `state_file` | string | `/var/lib/api-gateway/discovery-state.json` | Файл последнего удачного результата (аварийный фолбэк); `""` отключает персист | `/var/lib/api-gateway/discovery-state.json` |

Если `discovery.enabled: true`, статические `targets` и `routing.rules` можно не заполнять. При включённом discovery достаточно даже пустой секции `discovery: { enabled: true }` — остальные поля подставятся.

**Модуль discovery.** `discovery.module: <name>` заменяет Docker-провайдер на скомпилированный модуль; параметры модуля — в `plugins.<name>`. Модуль отдаёт сервисы (`name`, `address`, `path_prefix`, `strip_path`), из них собираются таргеты и правила. Имя модуля проверяется на старте и в `gateway --check`. Смена `discovery.module` требует рестарта: SIGHUP перечитывает только статический конфиг. Готовый модуль — `modules/file` (JSON-файл, см. `docs/modules.md`).

**Аварийный фолбэк.** Последний удачный результат discovery атомарно пишется в `state_file` и применяется при старте, поэтому маршруты переживают рестарт при недоступном Docker/Podman. Каталог `state_file` должен быть writable (смонтируйте volume). Ограничение: первый холодный старт без файла состояния и с недоступным Docker останется без обнаруженных маршрутов.

### Labels

Маркер контейнера — `gateway.enable: "true"` (принимаются `true`/`1`/`yes`, регистр не важен).

| Label | Обязателен | Смысл | По умолчанию |
|---|---|---|---|
| `gateway.enable` | да | Опт-ин контейнера | — |
| `gateway.name` | нет | Имя таргета | `service_name_labels`, иначе имя контейнера |
| `gateway.port` | да | Порт | единственный exposed TCP-порт |
| `gateway.scheme` | нет | `http` или `https` | `http` |
| `gateway.timeout` | нет | Таймаут запроса к цели | `discovery.default_timeout` |
| `gateway.health` | нет | Health-путь или полный URL | — |
| `gateway.weight` | нет | Вес таргета (`0`/отрицательный исключает) | `1` |

Роутеры задаются коротко (`gateway.<field>` → роутер `default`) или именованно (`gateway.router.<id>.<field>`): `host`, `path_prefix`, `methods`, `strip_path`, `auth.required`, `auth.roles`, `auth.roles_all`, `auth.strip_token`, `rate_limit.rps`, `rate_limit.burst`. Роутер без `host` и `path_prefix` пропускается.

## Поведение и оговорки

- **Порядок middleware.** Снаружи внутрь: инвалидация кеша permissions, Basic Auth, recovery, request id, tracing, метрики активных запросов, `/metrics`, глобальный лимит, статика, CORS-preflight, проксирование. Поэтому Basic Auth защищает и `/metrics`, и статику.
- **Рейт-лимиты.** Per-route лимит — token bucket на IP клиента; IP берётся из последнего непустого значения `X-Forwarded-For`, иначе из `RemoteAddr`. Глобальный лимит — один на процесс. Per-route отдаёт 429 без `Retry-After`; глобальный — 429 с `Retry-After: 1`. Лимитеры по IP очищаются после часа простоя.
- **Access log.** Выключен по умолчанию: каждая запись — это аллокации на горячем пути. Включайте для отладки, а не в проде под нагрузкой.
- **Тело запроса для аудита.** Читается только для `POST`, `PUT`, `PATCH`, `QUERY` и ограничено `max_request_body_size`; в событие попадает только JSON-объект короче 64 KiB.
- **Метрики.** `/metrics` в формате `expvar`, `/metrics/prometheus` — Prometheus с гистограммами; при `metrics_allowed_ips` доступ ограничен по IP для обоих.
