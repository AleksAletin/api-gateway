# API Gateway

[![CI](https://github.com/sarnas-it/api-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/sarnas-it/api-gateway/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26-00ADD8.svg)](go.mod)

**A small API gateway in Go with built-in JWT auth, RBAC and rate limiting.**
One binary (or a `scratch` image), one YAML config, no separate auth service.
Extensible with compile-time modules via the `xgate` builder. It runs in
production at [sarnas.ru](https://sarnas.ru).

Русская версия: [README.md](README.md)

## Benchmark

Proxy-only, one route to an instant backend, 2 CPU cores and 768 MiB per gateway,
`wrk` with 300 connections. Best of five runs; run-to-run noise is about ±10 %,
so compare relative gaps, not absolute numbers.

| | `api-gateway` | Others |
|---|---:|---:|
| Proxying, c300 | **24,068 req/s** | Nginx 27,216 · Kong 25,322 · Envoy 25,272 · Traefik 24,811 |
| Cost of built-in JWT | **−15.1 %** | Envoy `jwt_authn` −19.7 %, Kong `jwt` −28.9 % |
| External synchronous auth | n/a | Nginx `auth_request` −89.5 %, Traefik `forwardAuth` −93.8 % |
| Peak memory, c300 | 121.5 MiB | 15.8 (Nginx) – 314.1 (Kong) MiB |

What this does and does not show: `api-gateway` is about 12 % behind Nginx on
raw proxying and within 3–5 % of Traefik, Envoy and Kong. Validating a JWT
in-process is cheap everywhere; the expensive pattern is a network hop to an
auth service on every request. The backend answers instantly and there is no
TLS, so the numbers measure gateway overhead, not a real workload.

Full methodology, configs and reproduction scripts:
[benchmarks/2026-09-gateway-comparison](benchmarks/2026-09-gateway-comparison/README.md)
(the report itself is in Russian; configs and scripts are language-neutral).

## Features

- Routing by path prefix and by `Host` (including wildcards like `*.example.com`), plus `path_regex` (RE2), header and query matchers
- Per-route JWT auth and role checks (`auth.roles` = any of, `auth.roles_all` = all of)
- Identity federation: accept external JWTs (HMAC, or RSA/ECDSA via remote `jwks_url`) and map them onto internal users
- Per-route token-bucket rate limiting plus a global limit
- Load-balancing policies — `round_robin`/`random`/`least_conn`/`ip_hash`/`sticky` (HMAC-signed `xg_target` cookie) — and retries of idempotent methods on transport errors
- Health checks and a circuit breaker that trips on transport errors only
- Automatic TLS: Let's Encrypt via HTTP-01/TLS-ALPN-01 for exact domains and DNS-01 for wildcards (built-in reg.ru, more providers as xgate modules); TLS policy, mTLS and a separate mTLS listener for workers
- Compile-time modules (`xgate`): DNS-01 providers, auth connectors, discovery providers, HTTP middleware — no runtime plugins, zero hot-path overhead
- h2c/gRPC to backends, HTTP/3 (QUIC) listener, gzip response compression
- Docker/Podman service discovery by container labels, Traefik-style
- CORS allowlist, Basic Auth, JWT claims forwarded as headers
- Static files / SPA serving, webhooks and NATS events
- Metrics: `/metrics` (expvar) and `/metrics/prometheus` with histograms, IP/CIDR allowlist
- Loopback admin API with atomic config reload; graceful shutdown, structured logs (Zap), OpenTelemetry tracing
- `-check` / `-strict` flags to validate a config in CI before deploy

## Quick start

```bash
# 1. Any backend on :9000
docker run -d --rm --network host --name echo traefik/whoami --port 9000

# 2. Config: one target, one route
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
  required: false
YAML

# 3. Gateway
git clone https://github.com/sarnas-it/api-gateway && cd api-gateway
docker build -t api-gateway .
docker run -d --rm --network host --name gw \
  -v $(pwd)/../config.yaml:/etc/proxy/config.yaml:ro \
  api-gateway

curl -i localhost:8080/
```

Validate a config without starting the gateway (handy for CI):

```bash
api-gateway -config /etc/proxy/config.yaml -check          # exit 0/1
api-gateway -config /etc/proxy/config.yaml -check -strict  # unknown keys are errors too
```

`${VAR}` references must be defined in the environment: an unresolved variable
is a load error (fail fast), not a silent literal.

### Building with modules (`xgate`)

`xgate` is a compile-time builder in the spirit of `xcaddy`: it generates a
`main.go` with blank imports of the chosen modules and compiles the binary.

```bash
go build -o bin/xgate ./cmd/xgate
bin/xgate build --with github.com/acme/gateway-module@v1.0.0 --output bin/api-gateway-custom
```

See [“Modules and the xgate builder”](#modules-and-the-xgate-builder) below and
[`docs/xgate.md`](docs/xgate.md).

Docs (Russian): [quick start](docs/api-gateway-quickstart.md),
[configuration reference](docs/api-gateway-configuration.md),
[scenarios](docs/api-gateway-scenarios.md),
[dashboard](docs/api-gateway-dashboard.md). The fully commented example config is
[`config.local.example.yaml`](config.local.example.yaml).

## When to use it, and when not to

Good fit: a small gateway in front of a handful of services, with JWT and roles
per route, rate limiting, a circuit breaker, weighted balancing, label-based
discovery and automatic TLS certificates.

Not a fit: Kubernetes Ingress / Gateway API, a runtime plugin ecosystem like
Kong's, or an ACME server for other hosts. Use Traefik, Envoy or Kong for those.

## Configuration

One YAML file, path set by `-config`. Top-level sections: `application`,
`server`, `compression`, `plugins`, `http3`, `admin`, `tls`, `static`,
`targets`, `jwt`, `basic_auth`, `logging`, `headers`, `routing`, `permissions`,
`webhooks`, `discovery`, `identity`. Durations are Go duration strings
(`500ms`, `5s`, `5m`).

Full field-by-field reference:
[docs/api-gateway-configuration.md](docs/api-gateway-configuration.md).

## JWT auth, roles and identity federation

Tokens are accepted from `Authorization: Bearer …` or the `cml_access` cookie
and verified on every request: HMAC (`HS256/384/512`) with `jwt.secret_key`, or
RSA/ECDSA/Ed25519 with `jwt.public_key_file`. `exp`, `iss` and `aud` checks are
optional.

A token can be required globally (`jwt.required`) or per route
(`auth.required`). On a route that does not require it, an invalid token is
ignored and the request proceeds anonymously; on a route that does, it gets a
`401`.

Roles come from the `roles` claim (string or array): `auth.roles` — **any**
listed role is enough, `auth.roles_all` — **all** are required; with both, both
conditions must hold.

Claims are mapped to backend headers (`jwt.claim_mappings` +
`headers.claim_to_header`); `headers.strip_authorization` and
`auth.strip_token` remove the token from proxied requests, and
`headers.sign_header` / per-route `sign_v3` add an HMAC identity signature for
internal services.

The `identity` section accepts **external** JWTs from partner providers (their
own `secret_key`/`public_key_file`, or RSA/ECDSA via a remote `jwks_url`) and
maps them onto internal users: resolve by `(subject_provider, sub)` with an
email fallback through a cached passport user lookup (`identity.user_lookup`).
The request then flows like any authenticated one — roles, headers,
permissions.

## Routing: matchers, balancing, retries

Rule matchers combine with AND: `host` (wildcards included), `methods`,
`headers`, `query` and one of `path_prefix`/`path_regex` (RE2, compiled at
config load — a bad expression fails startup and `-check`). Among matching
rules the most specific wins: `host` first, then more header/query matchers,
then `path_regex`, then the longest `path_prefix`.

Rules with identical matchers and different targets form a balancing pool. The
pool policy is `lb_policy`: `round_robin` (default, weighted), `random`,
`least_conn` (by in-flight requests), `ip_hash` (deterministic by client IP),
`sticky` (pinned via an `xg_target` cookie HMAC-signed by the process — clients
can neither read nor forge it). `retries: 1..5` retries idempotent methods
(GET/HEAD/OPTIONS/TRACE) on transport errors.

Routes that stream large bodies (WebDAV and the like) get their own
`max_request_body_size`, `read_timeout`/`write_timeout`, `preserve_host` and
`buffer_request_body: false` (streamed, not truncated — but audit webhooks will
not see such bodies).

## Rate limiting

Two levels: per-route `rate_limit` — a token bucket per client IP (the IP comes
from `X-Forwarded-For` only when it arrives from a trusted proxy in
`server.trusted_proxies`, otherwise from `RemoteAddr`), and
`routing.global_limit` — a single process-wide limit. Per-route answers `429`
without `Retry-After`, the global one answers `429` with `Retry-After: 1`.
Per-IP limiters are evicted after an hour idle.

## CORS

`headers.cors` is an origin allowlist: an exact origin is reflected and gets
`Access-Control-Allow-Credentials`, `*` is returned without credentials, an
origin outside the list gets no CORS headers. Any `OPTIONS` is treated as a
preflight and answered `200`. With `application.env: dev` and no `cors`
section, a lenient origin-reflecting mode is enabled.

## Basic Auth

`basic_auth` protects administrative paths with a constant-time comparison over
SHA-256 of the login and password; `skip_paths` lists exceptions (exact match
or `path/` prefix). It sits in the outer middleware layer, so it covers
everything including `/metrics` and static files; after a successful check the
`Authorization` header is removed from the proxied request.

## HTTPS with automatic certificates (ACME)

The `tls` section serves HTTPS with Let's Encrypt certificates: exact domains
are handled by autocert (HTTP-01/TLS-ALPN-01), wildcards (`*.example.com`) by
certmagic over DNS-01. DNS-01 providers: built-in `regru`, plus libdns modules
compiled with `xgate --with` (Cloudflare, deSEC, DigitalOcean, Route53 — see
“Modules and the xgate builder”). Two servers start: HTTPS on `port` and HTTP
on `http_port` for the ACME challenge and redirects; `staging: true` or a
custom `directory_url` selects another ACME CA for testing.

Additionally: TLS policy (`min_version`, `cipher_suites`, `curves`), mTLS on
the main listener (`client_auth` + `client_ca_file`), and a separate mTLS
listener for workers (`worker_port` + `worker_client_ca_file`) that serves only
`/api/v1/workers/*` — everything else gets `404`, even with a valid client
certificate. Full field reference:
[docs/api-gateway-configuration.md](docs/api-gateway-configuration.md#tls).

## Modules and the xgate builder

`xgate` is a compile-time builder in the spirit of `xcaddy`: it generates a
`main.go` with blank imports of the selected modules and compiles the binary.
There are no runtime plugins — zero hot-path overhead — and the core (proxying,
JWT, RBAC, rate limiting, audit) stays built in.

```bash
go build -o bin/xgate ./cmd/xgate

bin/xgate build \
  --with code.sarnas.ru/xgate-modules/dns-cloudflare=./modules/dns/cloudflare \
  --output bin/api-gateway-custom
```

`--with module[@version][=replacement]` may be repeated; without a version the
latest is used, `=../path` substitutes a local checkout. The build runs in a
temporary Go module with a `replace` to the local gateway source, so the
working repo's `go.mod` is untouched. Instead of many `--with` flags you can
keep a manifest `xgate.yaml` (example: [`xgate.example.yaml`](xgate.example.yaml));
the build writes an `xgate.lock` next to it with the `source_sha`, the chosen
modules and the full transitive dependency graph. `xgate list` shows the
manifest, pinned versions and the dependency count.

### Module types

A module is a plain Go package that registers itself in `init()` via
`plugin.Register` and implements one of the [`pkg/plugin`](pkg/plugin)
interfaces:

| Type | Interface | Enabled via |
|---|---|---|
| DNS-01 provider | `plugin.DNSProvider` | `tls.dns_provider: "<name>"` |
| Auth connector | `plugin.AuthConnector` | `auth.connector: "<name>"` on a route |
| Discovery provider | `plugin.DiscoveryProvider` | `discovery.module: "<name>"` |
| HTTP middleware | `plugin.HTTPMiddleware` (`Wrap`) | wraps the HTTP/HTTPS/HTTP/3 listeners |

Module parameters live in the `plugins.<name>` config section and are read in
`Configure(map[string]string)`; an unknown name is a startup error. Sections
are applied once before the listeners start: `SIGHUP` does not re-read them —
changing `plugins:` requires a restart.

An auth connector is the only authenticator of its route (JWT is not checked):
the module returns claims (`id`, optionally `email` and `roles`) that then flow
exactly like JWT claims — header mapping, roles, permissions, signing. No
identity or a connector error means `401`.

### Built-in modules

| Module | Type | Directory |
|---|---|---|
| Cloudflare | DNS-01 | `modules/dns/cloudflare` |
| deSEC | DNS-01 | `modules/dns/desec` |
| DigitalOcean | DNS-01 | `modules/dns/digitalocean` |
| Route53 | DNS-01 | `modules/dns/route53` |
| Static API keys | auth connector | `modules/apikey` |
| File-based discovery | discovery | `modules/file` |
| Middleware template | HTTP middleware | `modules/example` |

To write your own: copy `modules/example`, implement the interface, register in
`init()`. Details — [`docs/xgate.md`](docs/xgate.md), module index —
[`docs/modules.md`](docs/modules.md), ecosystem design —
[`docs/plugin-ecosystem.md`](docs/plugin-ecosystem.md).

## Protocols and compression

- **h2c/gRPC**: `server.h2c: true` enables cleartext HTTP/2 on the client
  listener; `protocol: h2c` on a target speaks HTTP/2 to the backend
  (streaming and trailers are forwarded; TLS to gRPC backends is not
  supported yet).
- **HTTP/3 (QUIC)**: `http3.enabled: true` starts a UDP listener on the same
  TLS config and adds `Alt-Svc: h3` to HTTP/1.1/2 responses. Requires UDP
  forwarding and a sufficient `net.core.rmem_max`.
- **gzip**: `compression.enabled: true` compresses responses for clients
  sending `Accept-Encoding: gzip` (level and `min_size` configurable);
  `Vary: Accept-Encoding` is added automatically.

## Static files and SPA

The `static` section serves files before proxying (but after the global
limit): SPA fallback to `index_file` for unknown paths, flat `.html` files
(`about.html` for `/about`), `Cache-Control: max-age` from `max_age`. Paths in
`skip_prefixes` go to the proxy; when a request matches a rule with a `Host`,
static serving is skipped — host-based routing keeps working with static files
mounted.

## Reliability: health checks and circuit breaker

`application.health_check: true` enables background checks of targets that set
`health_check` (path or full URL); an unhealthy target leaves the balancing
pool until it recovers. `application.circuit_breaker: true` trips the circuit
on transport errors (502/503/504 also count as target failures) and probes
recovery with a half-open request.

## Permissions service

With `permissions.enabled: true` the gateway injects a header with the user's
effective permissions into the proxied request (`header_name`, default
`X-User-Permissions`): the `id` claim is taken from the verified identity,
`{method} {service_url}{path}` is called (the `{user_id}` placeholder is
required), and the result is cached per user for `cache_ttl`. Method, path and
the API-key header (`api_key_header`) are configurable; the default is
`GET .../api/v1/users/{user_id}/effective-permissions` with `X-API-Key`.

Any permissions-service error (network, timeout, non-200) does not block the
request — it proceeds without the header. The cache is flushed via
`POST /_cache/permissions/invalidate` with the `X-Invalidate-Token`:
`?user_id=42` for one user, no parameter for the whole cache. Service contract
and all fields: [docs/api-gateway-configuration.md](docs/api-gateway-configuration.md#permissions).

## Webhooks and audit

The `webhooks` section publishes `on_request`/`on_response` events to an HTTP
webhook or NATS: filters by method, response status (`on_status_codes`) and
`exclude_paths`; request (`changes`) and response (`response_body`) bodies are
optional — valid JSON only, responses up to 64 KiB. HTTP webhooks support
batching (`batch_size`, `flush_interval`) with a bounded queue and
backpressure; `async: true` takes delivery off the request hot path. Event
schema and examples:
[docs/api-gateway-configuration.md](docs/api-gateway-configuration.md#webhooks).

## Service discovery (Docker/Podman)

The gateway discovers backends from container labels — like Traefik's Docker
provider. It connects to the Docker/Podman API over a unix socket, finds
containers marked `gateway.enable=true`, builds targets and routing rules from
their labels and applies them to the running proxy. Discovered entries
**complement** the static config; on a target-name conflict the static config
wins, and a discovered service registering the same route as a static one joins
the shared pool instead of overriding it.

Targets are addressed by service name (`http://<name>:<port>`), so replicas of
one service are spread by Docker/Podman DNS. Different targets on one route are
balanced by the gateway itself (weighted round-robin over healthy candidates;
`weight: 0` excludes a target). The last good discovery result is persisted to
`state_file` and applied at startup, so routes survive a restart even when
Docker/Podman is unavailable.

Config reference, label list and examples:
[docs/api-gateway-configuration.md](docs/api-gateway-configuration.md#discovery)
and the “Service discovery” section of [README.md](README.md).

## Observability: metrics, logs, tracing, admin API

`application.metrics_enabled: true` enables metrics and opens two endpoints:
`/metrics` (expvar, for the dashboard) and `/metrics/prometheus` (Prometheus
format with the `gateway_request_duration_seconds` histogram, counters and
gauges; the `route` label is coarsened to keep cardinality low). Metrics are
off by default — collection adds work to every request.

Both endpoints are restricted by `application.metrics_allowed_ips` — exact IPs
and CIDR ranges (`["10.0.0.5", "172.30.0.0/24"]`); an empty list lifts the
restriction. In TLS mode both answer on the HTTP port for allowed IPs, so
monitoring can scrape them over the internal network without a certificate;
other HTTP-port requests are redirected to HTTPS. Global `basic_auth` protects
the metrics endpoints too.

Logging is Zap: `logging.level`, `logging.format` (`json` or `console`; a bad
value fails startup), and a per-request `access_log` that is off by default
because of hot-path allocations. OpenTelemetry tracing is enabled by the
`OTEL_EXPORTER_OTLP_ENDPOINT` environment variable, pprof by `PPROF_ADDR`.

`admin.enabled: true` starts a loopback admin API (`127.0.0.1:2019`):
`GET /health`, `GET /status`, `GET /config` (no secrets), and `POST /reload` —
atomically applies what can change on the fly (`targets`, `routing`, limits,
CORS, static, headers…); changes to immutable fields are rejected with
`requires restart` and the old config stays. `SIGHUP` does the same reload;
`SIGINT`/`SIGTERM` trigger a graceful shutdown with a 30-second timeout.

## Dashboard

A separate read-only binary `cmd/dashboard` shows a config summary, the last
saved discovery state and live gateway metrics — without touching or restarting
the gateway.

```bash
make dashboard
make dashboard-run \
  CONFIG=config.local.yaml \
  DASHBOARD_DISCOVERY_STATE=/var/lib/api-gateway/discovery-state.json
```

Endpoints: `GET /` — HTML overview, `GET /api/status` — the same snapshot as
JSON, `GET /healthz` — `200 ok`. Flags and packaging:
[docs/api-gateway-dashboard.md](docs/api-gateway-dashboard.md).

## Development

```bash
go mod download
go run ./cmd/gateway/ -config config.local.yaml
make lint
make test
```

## Contributing

Issues and PRs are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).
Tasks marked `good first issue` are a good place to start.

## License

MIT
