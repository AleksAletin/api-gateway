package config

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config представляет основную структуру конфигурации
type Config struct {
	App         `yaml:"application"`
	Server      ServerConfig      `yaml:"server"`
	TLS         *TLSConfig        `yaml:"tls,omitempty"`
	Static      *StaticConfig     `yaml:"static,omitempty"`
	Targets     []TargetConfig    `yaml:"targets"`
	JWT         JWTConfig         `yaml:"jwt"`
	BasicAuth   BasicAuthConfig   `yaml:"basic_auth"`
	Logging     LoggingConfig     `yaml:"logging"`
	Headers     HeadersConfig     `yaml:"headers"`
	Routing     RoutingConfig     `yaml:"routing"`
	Permissions PermissionsConfig `yaml:"permissions"`
	Identity    IdentityConfig    `yaml:"identity"`
	Webhooks    []WebhookConfig   `yaml:"webhooks"`
	Discovery   *DiscoveryConfig  `yaml:"discovery,omitempty"`
	Compression CompressionConfig `yaml:"compression"`
	Admin       AdminConfig       `yaml:"admin"`
	HTTP3       HTTP3Config       `yaml:"http3"`
	// Plugins — конфигурация compile-time модулей: имя модуля → параметры.
	Plugins map[string]map[string]string `yaml:"plugins"`
}

// HTTP3Config — HTTP/3 (QUIC) поверх того же TLS-конфига.
type HTTP3Config struct {
	Enabled bool `yaml:"enabled"`
	// Port — UDP-порт; 0 → tls.port.
	Port int `yaml:"port"`
}

// AdminConfig — loopback admin API (status/reload).
type AdminConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Token   string `yaml:"token"`
}

// CompressionConfig — gzip-сжатие ответов.
type CompressionConfig struct {
	Enabled bool `yaml:"enabled"`
	// Level — уровень gzip 1..9; 0 → 5.
	Level int `yaml:"level"`
	// MinSize — минимальный известный Content-Length для сжатия; 0 → 1024.
	MinSize int `yaml:"min_size"`
}

// DiscoveryConfig конфигурация service discovery (Docker/Podman по labels).
type DiscoveryConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"`
	// Module — имя compile-time xgate-модуля plugin.DiscoveryProvider.
	// Если задан, встроенный Docker-провайдер не создаётся: источником
	// сервисов становится модуль.
	Module            string        `yaml:"module"`
	Host              string        `yaml:"host"`
	APIVersion        string        `yaml:"api_version"`
	LabelPrefix       string        `yaml:"label_prefix"`
	ServiceNameLabels []string      `yaml:"service_name_labels"`
	Network           string        `yaml:"network"`
	Debounce          time.Duration `yaml:"debounce"`
	ResyncInterval    time.Duration `yaml:"resync_interval"`
	DefaultTimeout    time.Duration `yaml:"default_timeout"`
	// StateFile — путь к файлу с последним удачным результатом discovery
	// (аварийный фолбэк: маршруты переживают рестарт при недоступном Docker).
	// Пустая строка отключает персист.
	StateFile string `yaml:"state_file"`
}

// TLSConfig конфигурация TLS с автосертификатами (Let's Encrypt)
type TLSConfig struct {
	Enabled      bool     `yaml:"enabled"`       // включить HTTPS
	Port         int      `yaml:"port"`          // HTTPS порт (по умолчанию 443)
	HTTPPort     int      `yaml:"http_port"`     // HTTP порт для redirect (по умолчанию 80)
	Domains      []string `yaml:"domains"`       // домены для сертификатов
	Email        string   `yaml:"email"`         // email для Let's Encrypt (обязательно)
	CacheDir     string   `yaml:"cache_dir"`     // директория для кеша сертификатов
	Staging      bool     `yaml:"staging"`       // true = staging CA, false = production Let's Encrypt
	RedirectHTTP bool     `yaml:"redirect_http"` // автоматический redirect HTTP → HTTPS
	// DirectoryURL — необязательный ACME directory URL. Если задан, перекрывает
	// выбор CA по staging. Пусто = staging ? Let's Encrypt staging : production.
	DirectoryURL string `yaml:"directory_url"`
	// WorkerPort — порт отдельного HTTPS-листенера для протокола воркеров
	// (/api/v1/workers/*) с обязательным клиентским сертификатом (mTLS).
	// 0 (по умолчанию) — листенер выключен.
	WorkerPort int `yaml:"worker_port"`
	// WorkerClientCAFile — PEM-файл с CA (или набором CA), которым проверяются
	// клиентские сертификаты воркеров. Обязателен при worker_port > 0.
	WorkerClientCAFile string `yaml:"worker_client_ca_file"`

	// DNSProvider включает ACME DNS-01 для wildcard-доменов. Сейчас
	// поддерживается "regru". Без него wildcard запрещён, как и раньше.
	DNSProvider string `yaml:"dns_provider"`
	// DNSUsername/DNSPassword — доступ к API провайдера. Секреты подставляются
	// из окружения: "${REGRU_USER}", "${REGRU_PASSWORD}".
	DNSUsername string `yaml:"dns_username"`
	DNSPassword string `yaml:"dns_password"`
	// DNSConfig — параметры внешнего libdns-провайдера (например, api_token).
	DNSConfig map[string]string `yaml:"dns_config"`
	// DNSPropagationTimeout — сколько ждать появления TXT-записи; 0 → 2 минуты.
	DNSPropagationTimeout time.Duration `yaml:"dns_propagation_timeout"`

	// WildcardCertFile/WildcardKeyFile — готовый сертификат для wildcard-доменов
	// (например, выпущенный certbot/acme.sh вручную). Взаимоисключающая
	// альтернатива DNS-01: файлы читаются при старте, ACME не вызывается.
	WildcardCertFile string `yaml:"wildcard_cert_file"`
	WildcardKeyFile  string `yaml:"wildcard_key_file"`

	// MinVersion — минимальная версия TLS: "1.2" (по умолчанию) или "1.3".
	MinVersion string `yaml:"min_version"`
	// CipherSuites — имена TLS 1.0–1.2 cipher suites; TLS 1.3 не настраивается.
	CipherSuites []string `yaml:"cipher_suites"`
	// Curves — предпочтительные кривые: X25519, P-256, P-384, P-521.
	Curves []string `yaml:"curves"`
	// ClientAuth — mTLS на основном листенере: none/request/require/verify.
	ClientAuth string `yaml:"client_auth"`
	// ClientCAFile — PEM-файл CA для проверки клиентских сертификатов.
	ClientCAFile string `yaml:"client_ca_file"`
}

// UpstreamTLSConfig — TLS к конкретному бэкенду.
type UpstreamTLSConfig struct {
	CAFile             string `yaml:"ca_file"`
	ServerName         string `yaml:"server_name"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CertFile           string `yaml:"cert_file"`
	KeyFile            string `yaml:"key_file"`
}

// ParseTLSVersion переводит "1.2"/"1.3" в tls.VersionTLS12/13.
func ParseTLSVersion(v string) (uint16, error) {
	switch v {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version %q, want 1.2 or 1.3", v)
	}
}

// ParseCipherSuites переводит имена Go cipher suites в ID. TLS 1.3 suites
// настраивать нельзя — они игнорируются Go, поэтому явно отклоняем.
func ParseCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil
	}
	known := make(map[string]uint16)
	for _, cs := range tls.CipherSuites() {
		known[cs.Name] = cs.ID
	}
	out := make([]uint16, 0, len(names))
	for _, name := range names {
		if strings.HasPrefix(name, "TLS_AES_") || strings.HasPrefix(name, "TLS_CHACHA20_") {
			return nil, fmt.Errorf("TLS 1.3 cipher suite %q is not configurable", name)
		}
		id, ok := known[name]
		if !ok {
			return nil, fmt.Errorf("unknown cipher suite %q", name)
		}
		out = append(out, id)
	}
	return out, nil
}

// ParseCurves переводит имена кривых в tls.CurveID.
func ParseCurves(names []string) ([]tls.CurveID, error) {
	if len(names) == 0 {
		return nil, nil
	}
	known := map[string]tls.CurveID{
		"X25519": tls.X25519,
		"P-256":  tls.CurveP256,
		"P-384":  tls.CurveP384,
		"P-521":  tls.CurveP521,
	}
	out := make([]tls.CurveID, 0, len(names))
	for _, name := range names {
		id, ok := known[name]
		if !ok {
			return nil, fmt.Errorf("unknown curve %q", name)
		}
		out = append(out, id)
	}
	return out, nil
}

// ParseClientAuth переводит режим mTLS в tls.ClientAuthType.
func ParseClientAuth(v string) (tls.ClientAuthType, error) {
	switch v {
	case "", "none":
		return tls.NoClientCert, nil
	case "request":
		return tls.RequestClientCert, nil
	case "require":
		return tls.RequireAnyClientCert, nil
	case "verify":
		return tls.RequireAndVerifyClientCert, nil
	default:
		return 0, fmt.Errorf("unsupported client_auth %q, want none/request/require/verify", v)
	}
}

// StaticApp конфигурация SPA фронтенда
type StaticApp struct {
	PathPrefix string `yaml:"path_prefix"` // URL путь (например / или /admin)
	RootDir    string `yaml:"root_dir"`    // директория со статикой
	IndexFile  string `yaml:"index_file"`  // fallback для SPA (по умолчанию index.html)
	MaxAge     int    `yaml:"max_age"`     // Cache-Control max-age в секундах
}

// StaticConfig конфигурация раздачи статических SPA
type StaticConfig struct {
	Apps         []StaticApp `yaml:"apps"`
	SkipPrefixes []string    `yaml:"skip_prefixes,omitempty"` // пути, которые НЕ отдавать статикой (например /api)
}
type App struct {
	Env               string   `yaml:"env"`
	HealthCheck       bool     `yaml:"health_check"`
	CircuitBreaker    bool     `yaml:"circuit_breaker"`
	MetricsEnabled    bool     `yaml:"metrics_enabled"` // сбор метрик и /metrics эндпоинт; выкл. по умолчанию (доп. накладные расходы на запрос)
	MetricsAllowedIPs []string `yaml:"metrics_allowed_ips"`
	// MaxIdleConnsPerHost — размер пула keep-alive соединений к каждому таргету.
	// Должен быть не меньше пиковой конкурентности к таргету, иначе транспорт
	// постоянно переоткрывает соединения (CPU уходит в connect) и RPS падает
	// под нагрузкой. 0 → дефолт (1000).
	MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host"`
}

// ServerConfig конфигурация HTTP сервера
type ServerConfig struct {
	Port         int           `yaml:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
	IdleTimeout  time.Duration `yaml:"idle_timeout"`
	// MaxRequestBodySize — лимит тела запроса в байтах.
	// nil (ключ не задан) → значение по умолчанию 10 MiB;
	// 0 → без лимита; >0 → лимит в байтах.
	MaxRequestBodySize *int64 `yaml:"max_request_body_size"`
	// TrustedProxies — IP/CIDR прокси, которым доверяем X-Forwarded-For.
	// Пусто → XFF игнорируется, клиентский IP берётся из RemoteAddr.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// H2C включает cleartext HTTP/2 на обычном HTTP-листенере (без TLS).
	H2C bool `yaml:"h2c"`
}

// ParseTrustedProxies разбирает список IP/CIDR доверенных прокси. Одиночный
// адрес превращается в /32 (IPv4) или /128 (IPv6).
func ParseTrustedProxies(values []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(values))
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(v); err == nil {
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP or CIDR %q", raw)
		}
		bits := net.IPv6len * 8
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
			bits = net.IPv4len * 8
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

// defaultMaxRequestBodySize применяется, когда max_request_body_size не задан.
const defaultMaxRequestBodySize int64 = 10 << 20 // 10 MiB

// EffectiveMaxRequestBodySize возвращает действующий лимит тела запроса в
// байтах. nil трактуется как значение по умолчанию (10 MiB); значение <= 0
// означает отсутствие лимита.
func (s ServerConfig) EffectiveMaxRequestBodySize() int64 {
	if s.MaxRequestBodySize == nil {
		return defaultMaxRequestBodySize
	}
	return *s.MaxRequestBodySize
}

// TargetConfig конфигурация целевого сервера
type TargetConfig struct {
	Name        string        `yaml:"name"`         // уникальное имя таргета
	URL         string        `yaml:"url"`          // например: http://localhost:9001
	Timeout     time.Duration `yaml:"timeout"`      // таймаут для запросов к цели
	PathPrefix  string        `yaml:"path_prefix"`  // какой путь проксировать (опционально)
	StripPrefix bool          `yaml:"strip_prefix"` // удалять префикс при проксировании
	// Weight — вес таргета при взвешенной балансировке внутри одного route-пула
	// (правила с одинаковыми host, path_prefix и methods). nil (ключ не задан) →
	// значение по умолчанию 1; 0 или отрицательное → таргет исключается из
	// выбора; >0 → вес.
	Weight      *int   `yaml:"weight"`
	HealthCheck string `yaml:"health_check"` // URL для проверки здоровья
	// TLS — настройки TLS к HTTPS-бэкенду (свой CA, mTLS, skip-verify).
	TLS *UpstreamTLSConfig `yaml:"tls,omitempty"`
	// Protocol — протокол к бэкенду: "" (HTTP/1.1) или "h2c" (cleartext HTTP/2,
	// в том числе gRPC). h2c требует http:// URL.
	Protocol string `yaml:"protocol"`
	// Rest — «отдых» таргета в пуле при ответах 429/503. nil или
	// enabled: false — поведение выключено (по умолчанию).
	Rest *RestConfig `yaml:"rest,omitempty"`
}

// RestConfig настраивает вывод таргета из выбора в пуле («отдых») при
// ответах 429 и 503. Ответ с заголовком Retry-After выводит таргет ровно на
// указанное время (не дольше max); без заголовка пауза начинается с base и
// удваивается при повторах подряд (потолок — max); если с прошлого отдыха
// прошло больше max, счёт начинается заново с base. Отдых не меняет
// circuit breaker и health check: это мягкое исключение из пула, а не
// нездоровье. Если отдыхают все кандидаты пула, запрос идёт тому, кто
// вернётся раньше всех.
type RestConfig struct {
	Enabled bool          `yaml:"enabled"`
	Base    time.Duration `yaml:"base"` // пауза без Retry-After; по умолчанию 1m
	Max     time.Duration `yaml:"max"`  // потолок паузы и окно сброса; по умолчанию 30m
}

// EffectiveBase возвращает стартовую паузу без Retry-After (по умолчанию 1m).
func (r *RestConfig) EffectiveBase() time.Duration {
	if r == nil || r.Base <= 0 {
		return time.Minute
	}
	return r.Base
}

// EffectiveMax возвращает потолок паузы (по умолчанию 30m).
func (r *RestConfig) EffectiveMax() time.Duration {
	if r == nil || r.Max <= 0 {
		return 30 * time.Minute
	}
	return r.Max
}

// EffectiveWeight возвращает действующий вес таргета: nil трактуется как 1
// (значение по умолчанию). Явные 0 и отрицательные значения сохраняются —
// вызывающая сторона исключает такие таргеты из выбора.
func (t TargetConfig) EffectiveWeight() int {
	if t.Weight == nil {
		return 1
	}
	return *t.Weight
}

// RoutingConfig конфигурация маршрутизации
type RoutingConfig struct {
	Rules       []RoutingRule  `yaml:"rules"`                  // правила маршрутизации
	GlobalLimit *RateLimitRule `yaml:"global_limit,omitempty"` // глобальный лимит для всех запросов
}

// RoutingRule правило маршрутизации
type RoutingRule struct {
	Host       string         `yaml:"host,omitempty"`       // домен для матчинга (опционально)
	PathPrefix string         `yaml:"path_prefix"`          // путь для матчинга
	TargetName string         `yaml:"target_name"`          // имя таргета
	Methods    []string       `yaml:"methods"`              // HTTP методы (опционально)
	StripPath  bool           `yaml:"strip_path"`           // удалять префикс при проксировании
	Auth       *AuthRule      `yaml:"auth,omitempty"`       // per-route auth конфиг
	RateLimit  *RateLimitRule `yaml:"rate_limit,omitempty"` // per-route rate limit
	SignV3     *SignV3Config  `yaml:"sign_v3,omitempty"`    // per-route HMAC v3 подпись запроса

	// MaxRequestBodySize — лимит тела запроса для маршрута (байты).
	// nil — общий server.max_request_body_size, 0 — без лимита.
	// Нужен протоколам с большими телами (WebDAV PUT): поднимать общий лимит
	// ради одного маршрута пришлось бы для всех сервисов сразу.
	MaxRequestBodySize *int64 `yaml:"max_request_body_size,omitempty"`
	// ReadTimeout/WriteTimeout — дедлайны именно этого маршрута. Ставятся
	// через http.ResponseController и перекрывают общий server.read_timeout
	// (он остаётся коротким для фазы заголовков).
	ReadTimeout  time.Duration `yaml:"read_timeout,omitempty"`
	WriteTimeout time.Duration `yaml:"write_timeout,omitempty"`
	// PreserveHost сохраняет исходный Host в запросе к бэкенду (по умолчанию
	// подменяется на host таргета). Нужен протоколам, которые сверяют Host с
	// абсолютными ссылками в заголовках (WebDAV Destination в MOVE/COPY).
	PreserveHost bool `yaml:"preserve_host,omitempty"`
	// BufferRequestBody — читать тело в память перед проксированием (нужно
	// аудит-вебхукам). nil — true (обратная совместимость); false — тело
	// стримится в бэкенд без буферизации и обрезания.
	BufferRequestBody *bool `yaml:"buffer_request_body,omitempty"`

	// LBPolicy — политика выбора таргета в пуле: round_robin (по умолчанию),
	// random, least_conn, ip_hash, sticky (привязка клиента к таргету через
	// подписанную cookie).
	LBPolicy string `yaml:"lb_policy"`
	// Retries — число повторов при транспортной ошибке для идемпотентных
	// методов без тела (GET/HEAD/OPTIONS/TRACE). 0 — без повторов.
	Retries int `yaml:"retries"`

	// PathRegex — RE2-регулярное выражение по r.URL.Path. Взаимоисключающе с
	// path_prefix: либо префикс, либо регулярка. Паттерн не анкорится —
	// якори задаются в самом выражении (^...$).
	PathRegex string `yaml:"path_regex,omitempty"`
	// Headers — все перечисленные заголовки должны совпасть с точным
	// значением. Пустое значение — заголовок должен присутствовать.
	Headers map[string]string `yaml:"headers,omitempty"`
	// Query — все перечисленные параметры должны совпасть с точным
	// значением. Пустое значение — параметр должен присутствовать.
	Query map[string]string `yaml:"query,omitempty"`

	// pathRe — скомпилированный PathRegex; заполняется при Load/Validate.
	pathRe *regexp.Regexp
}

// BufferRequestBodyEnabled — эффективное значение buffer_request_body.
func (r RoutingRule) BufferRequestBodyEnabled() bool {
	if r.BufferRequestBody == nil {
		return true
	}
	return *r.BufferRequestBody
}

// EffectiveMaxRequestBodySize — лимит тела для маршрута (nil → лимит сервера).
func (r RoutingRule) EffectiveMaxRequestBodySize(serverLimit int64) int64 {
	if r.MaxRequestBodySize == nil {
		return serverLimit
	}
	return *r.MaxRequestBodySize
}

// SignV3Config — per-route подпись запроса HMAC v3 для внутренних сервисов
// на go-hmac-auth (заголовки X-Service-ID/X-Key-ID/X-User-Timestamp/
// X-User-Signature). Секрет задаётся только на сервере / в приватном конфиге.
type SignV3Config struct {
	ServiceID string `yaml:"service_id"`
	KeyID     string `yaml:"key_id"`
	Secret    string `yaml:"secret"`
}

// AuthRule конфигурация аутентификации для роута
type AuthRule struct {
	// Required — требовать ли JWT на маршруте. nil наследует глобальный
	// jwt.required; явные true/false переопределяют его.
	Required   *bool    `yaml:"required,omitempty"`
	Roles      []string `yaml:"roles,omitempty"`       // хотя бы одна из ролей (any-of)
	RolesAll   []string `yaml:"roles_all,omitempty"`   // все перечисленные роли (all-of)
	StripToken *bool    `yaml:"strip_token,omitempty"` // удалять токен (наследует глобальный если не указан)
	// Connector — имя compile-time xgate-модуля с plugin.AuthConnector.
	// Если задан, маршрут аутентифицируется только им: JWT для него не
	// проверяется, отсутствие или ошибка credentials — 401 (fail closed).
	Connector string `yaml:"connector,omitempty"`
}

// EffectiveRequired возвращает, требуется ли аутентификация на маршруте.
// Непустые roles/roles_all сами требуют токен: иначе правило с ролями
// молча пропускало бы анонимов при global jwt.required=false.
func (a *AuthRule) EffectiveRequired(global bool) bool {
	if a == nil {
		return global
	}
	if len(a.Roles) > 0 || len(a.RolesAll) > 0 {
		return true
	}
	if a.Required != nil {
		return *a.Required
	}
	return global
}

// BasicAuthConfig конфигурация Basic аутентификации
type BasicAuthConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Username  string   `yaml:"username"`
	Password  string   `yaml:"password"`
	SkipPaths []string `yaml:"skip_paths"` // пути, которые не требуют Basic Auth (с поддержкой префиксов)
}

// RateLimitRule конфигурация rate limiting для роута
type RateLimitRule struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"` // запросов в секунду
	Burst             int     `yaml:"burst"`               // burst размер
}

// JWTConfig конфигурация валидации JWT
type JWTConfig struct {
	SecretKey     string   `yaml:"secret_key"`      // симметричный ключ (HMAC)
	PublicKeyFile string   `yaml:"public_key_file"` // для RSA/ECDSA
	Algorithm     string   `yaml:"algorithm"`       // HS256, RS256 и т.д.
	ValidateExp   bool     `yaml:"validate_exp"`    // проверять срок действия
	ValidateIss   bool     `yaml:"validate_iss"`    // проверять issuer
	ExpectedIss   string   `yaml:"expected_iss"`    // ожидаемый issuer
	ValidateAud   bool     `yaml:"validate_aud"`    // проверять audience
	ExpectedAud   string   `yaml:"expected_aud"`    // ожидаемый audience
	ClaimMappings []string `yaml:"claim_mappings"`  // какие claims извлекать
	Required      bool     `yaml:"required"`        // требовать ли JWT
}

// CORSConfig настройки CORS
type CORSConfig struct {
	Enabled        bool     `yaml:"enabled"`
	AllowedOrigins []string `yaml:"allowed_origins"`
	AllowedMethods []string `yaml:"allowed_methods"`
	AllowedHeaders []string `yaml:"allowed_headers"`
	ExposeHeaders  []string `yaml:"expose_headers"`
	MaxAge         int      `yaml:"max_age"`
}

// PermissionsConfig конфигурация модуля разрешений (permission-service)
type PermissionsConfig struct {
	Enabled         bool          `yaml:"enabled"`
	ServiceURL      string        `yaml:"service_url"`
	Method          string        `yaml:"method"`
	Path            string        `yaml:"path"`
	CacheTTL        time.Duration `yaml:"cache_ttl"`
	HeaderName      string        `yaml:"header_name"`
	InvalidateToken string        `yaml:"invalidate_token"`
	APIKey          string        `yaml:"api_key"`
	APIKeyHeader    string        `yaml:"api_key_header"`
}

const (
	defaultPermissionsMethod       = "GET"
	defaultPermissionsPath         = "/api/v1/users/{user_id}/effective-permissions"
	defaultPermissionsAPIKeyHeader = "X-API-Key"
)

// IdentityConfig — федерация внешней идентичности (внешние JWT-провайдеры)
type IdentityConfig struct {
	Enabled    bool                     `yaml:"enabled"`
	Selection  []string                 `yaml:"selection"` // пусто = все enabled
	UserLookup IdentityUserLookupConfig `yaml:"user_lookup"`
	Providers  []IdentityProviderConfig `yaml:"providers"`
}

// IdentityUserLookupConfig — резолв email → наш пользователь через passport
type IdentityUserLookupConfig struct {
	ServiceURL string        `yaml:"service_url"`
	HMACSecret string        `yaml:"hmac_secret"`
	CacheTTL   time.Duration `yaml:"cache_ttl"`
}

// IdentityProviderConfig — один доверенный внешний JWT-провайдер
type IdentityProviderConfig struct {
	Name            string `yaml:"name"`
	Enabled         bool   `yaml:"enabled"`
	Issuer          string `yaml:"issuer"`
	Algorithm       string `yaml:"algorithm"`
	PublicKeyFile   string `yaml:"public_key_file"`
	SecretKey       string `yaml:"secret_key"`
	JwksURL         string `yaml:"jwks_url"`
	ValidateExp     bool   `yaml:"validate_exp"`
	ValidateIss     bool   `yaml:"validate_iss"`
	ExpectedIss     string `yaml:"expected_iss"`
	EmailClaim      string `yaml:"email_claim"`
	SubjectClaim    string `yaml:"subject_claim"`
	SubjectProvider string `yaml:"subject_provider"`
}

// HeadersConfig конфигурация заголовков
type HeadersConfig struct {
	StripAuthorization bool              `yaml:"strip_authorization"`
	ClaimToHeader      map[string]string `yaml:"claim_to_header"`
	AddHeaders         map[string]string `yaml:"add_headers"`
	SignHeader         string            `yaml:"sign_header"`
	CORS               *CORSConfig       `yaml:"cors,omitempty"`
}

// WebhookTrigger тип триггера для вебхука
type WebhookTrigger string

const (
	TriggerOnRequest  WebhookTrigger = "on_request"
	TriggerOnResponse WebhookTrigger = "on_response"
)

// WebhookTransport тип транспорта для вебхука
type WebhookTransport string

const (
	TransportNATS    WebhookTransport = "nats"
	TransportWebhook WebhookTransport = "webhook"
)

// WebhookConfig конфигурация вебхука/NATS публикации событий
type WebhookConfig struct {
	Name          string           `yaml:"name"`
	Transport     WebhookTransport `yaml:"transport"`
	NATSURL       string           `yaml:"nats_url"`
	Subject       string           `yaml:"subject"`
	WebhookURL    string           `yaml:"webhook_url"`
	Trigger       WebhookTrigger   `yaml:"trigger"`
	Methods       []string         `yaml:"methods"`
	OnStatusCodes []int            `yaml:"on_status_codes"`
	ExcludePaths  []string         `yaml:"exclude_paths"`
	Async         bool             `yaml:"async"`
	// IncludeRequestBody — включать в событие тело запроса (поле changes).
	// nil (не задано) = true: прежнее поведение (тело публиковалось всегда).
	// Явное false выключает публикацию тела запроса для этого вебхука.
	IncludeRequestBody *bool `yaml:"include_request_body"`
	// IncludeResponseBody — включать в событие тело ответа (поле response_body).
	// Тело собирается только для JSON-ответов и ограничено по размеру.
	// По умолчанию выключено — включение настраивается явно.
	IncludeResponseBody bool `yaml:"include_response_body"`
	// BatchSize включает батчинг HTTP-вебхуков: события копятся и уходят одним
	// POST телом {"count":N,"events":[...]}. 0/1 — по одному событию (старый формат).
	BatchSize int `yaml:"batch_size"`
	// FlushInterval — максимальная задержка перед отправкой неполной пачки.
	// По умолчанию 200ms (используется только при BatchSize > 1).
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// IncludeRequestBodyEnabled возвращает эффективное значение include_request_body
// (nil трактуется как true — обратная совместимость).
func (w WebhookConfig) IncludeRequestBodyEnabled() bool {
	if w.IncludeRequestBody == nil {
		return true
	}
	return *w.IncludeRequestBody
}

// LoggingConfig конфигурация логирования
type LoggingConfig struct {
	Level     string `yaml:"level"`      // debug, info, warn, error
	Format    string `yaml:"format"`     // json, console или text (алиас console)
	AccessLog bool   `yaml:"access_log"` // построчный лог каждого запроса; выкл. по умолчанию (аллокации на каждый запрос)
}

// Load загружает конфигурацию из файла. Второе возвращаемое значение —
// предупреждения о неизвестных YAML-ключах с точечными путями (например
// "headers.forward_headers"); вызывающая сторона должна залогировать их.
// Неизвестные ключи не являются ошибкой — конфиг по-прежнему загружается.
func Load(path string) (*Config, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Подстановка переменных окружения ${VAR_NAME}. Если переменная не задана
	// или пуста, конфигурация считается невалидной: молчаливый фолбэк на
	// литерал "${VAR}" опасен (его можно случайно использовать как секрет).
	// Экранирование литерала — "$${VAR}".
	var missing []string
	seenMissing := make(map[string]bool)
	resolved := os.Expand(string(data), func(key string) string {
		if key == "$" {
			return "$"
		}
		val, ok := os.LookupEnv(key)
		if !ok || val == "" {
			if !seenMissing[key] {
				seenMissing[key] = true
				missing = append(missing, key)
			}
			return ""
		}
		return val
	})
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, nil, fmt.Errorf("config references undefined environment variable(s): %s", strings.Join(missing, ", "))
	}

	cfg, warnings, err := parseConfig(resolved)
	if err != nil {
		return nil, nil, err
	}

	// Валидация конфигурации
	if err := cfg.validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, warnings, nil
}

// LoadLenient загружает конфигурацию «мягко». Отличия от Load:
//   - отсутствующие или пустые переменные окружения не считаются ошибкой —
//     соответствующий литерал "${VAR}" остаётся в тексте как есть;
//   - validate() не вызывается, поэтому конфиг без таргетов всё равно
//     разбирается.
//
// Предупреждения о неизвестных YAML-ключах и значения по умолчанию
// применяются так же, как у Load. Режим нужен read-only дашборду, который не
// должен требовать секретные переменные окружения гейтвея.
func LoadLenient(path string) (*Config, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Best-effort подстановка: не заданные (или пустые) переменные остаются
	// литералом "${VAR}". Экранирование "$${VAR}" по-прежнему даёт "${VAR}".
	resolved := os.Expand(string(data), func(key string) string {
		if key == "$" {
			return "$"
		}
		val, ok := os.LookupEnv(key)
		if !ok || val == "" {
			return "${" + key + "}"
		}
		return val
	})

	cfg, warnings, err := parseConfig(resolved)
	if err != nil {
		return nil, nil, err
	}
	return cfg, warnings, nil
}

// parseConfig разбирает YAML, собирает предупреждения о неизвестных ключах и
// применяет значения по умолчанию. Валидация здесь не выполняется — это
// ответственность вызывающей стороны (Load).
func parseConfig(resolved string) (*Config, []string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(resolved), &root); err != nil {
		return nil, nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	var cfg Config
	if root.Kind != 0 {
		if err := root.Decode(&cfg); err != nil {
			return nil, nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	warnings := unknownYAMLKeys(&root)

	// Устанавливаем значения по умолчанию
	cfg.setDefaults()

	return &cfg, warnings, nil
}

// unknownYAMLKeys обходит дерево YAML и возвращает точечные пути ключей, для
// которых нет соответствующего поля в структуре Config (по yaml-тегам).
func unknownYAMLKeys(root *yaml.Node) []string {
	if root == nil || root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}
	var warnings []string
	seen := make(map[string]bool)
	collectUnknownKeys(root.Content[0], reflect.TypeOf(Config{}), "", &warnings, seen)
	return warnings
}

// collectUnknownKeys рекурсивно сверяет узлы YAML со структурой typ.
// path — точечный путь от корня; warnings пополняется неизвестными ключами.
func collectUnknownKeys(node *yaml.Node, typ reflect.Type, path string, warnings *[]string, seen map[string]bool) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	switch typ.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return
		}
		fields := yamlFields(typ)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			fieldType, ok := fields[key]
			if !ok {
				if !seen[childPath] {
					seen[childPath] = true
					*warnings = append(*warnings, childPath)
				}
				continue
			}
			collectUnknownKeys(node.Content[i+1], fieldType, childPath, warnings, seen)
		}
	case reflect.Slice, reflect.Array:
		if node.Kind != yaml.SequenceNode {
			return
		}
		elem := typ.Elem()
		for _, item := range node.Content {
			collectUnknownKeys(item, elem, path, warnings, seen)
		}
	}
	// Map и скаляры: ключи карт произвольны, у скаляров вложенности нет.
}

// yamlFields строит карту "yaml-имя поля → тип поля" для структуры,
// разворачивая встроенные (anonymous/inline) структуры.
func yamlFields(typ reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name, opts, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			if field.Anonymous || strings.Contains(opts, "inline") {
				embedded := field.Type
				for embedded.Kind() == reflect.Pointer {
					embedded = embedded.Elem()
				}
				if embedded.Kind() == reflect.Struct {
					for k, v := range yamlFields(embedded) {
						fields[k] = v
					}
				}
			}
			continue
		}
		fields[name] = field.Type
	}
	return fields
}

// setDefaults устанавливает значения по умолчанию
func (c *Config) setDefaults() {
	if c.MaxIdleConnsPerHost <= 0 {
		c.MaxIdleConnsPerHost = 1000
	}
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 5 * time.Second
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 10 * time.Second
	}
	if c.Server.IdleTimeout == 0 {
		c.Server.IdleTimeout = 120 * time.Second
	}
	if c.Server.MaxRequestBodySize == nil {
		// Ключ не задан → дефолт 10 MiB. Явный 0 остаётся без лимита.
		size := defaultMaxRequestBodySize
		c.Server.MaxRequestBodySize = &size
	}
	if c.Compression.Level == 0 {
		c.Compression.Level = 5
	}
	if c.Compression.MinSize == 0 {
		c.Compression.MinSize = 1024
	}
	if c.Admin.Enabled && c.Admin.Addr == "" {
		c.Admin.Addr = "127.0.0.1:2019"
	}
	if c.HTTP3.Enabled && c.HTTP3.Port == 0 {
		if c.TLS != nil && c.TLS.Port > 0 {
			c.HTTP3.Port = c.TLS.Port
		} else {
			c.HTTP3.Port = 443
		}
	}

	if c.TLS != nil && c.TLS.Enabled {
		if c.TLS.Port == 0 {
			c.TLS.Port = 443
		}
		if c.TLS.HTTPPort == 0 {
			c.TLS.HTTPPort = 80
		}
		if c.TLS.CacheDir == "" {
			c.TLS.CacheDir = "/var/lib/api-gateway/certs"
		}
	}

	if c.Static != nil {
		for i := range c.Static.Apps {
			if c.Static.Apps[i].IndexFile == "" {
				c.Static.Apps[i].IndexFile = "index.html"
			}
		}
	}

	// Устанавливаем таймауты для таргетов, если не заданы
	for i := range c.Targets {
		if c.Targets[i].Timeout == 0 {
			c.Targets[i].Timeout = 30 * time.Second
		}
		if c.Targets[i].Weight == nil {
			// Ключ не задан → дефолт 1. Явный 0 (или отрицательный)
			// сохраняется и исключает таргет из выбора.
			weight := 1
			c.Targets[i].Weight = &weight
		}
	}

	if c.JWT.Algorithm == "" {
		c.JWT.Algorithm = "HS256"
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	// Формат логирования нормализуем один раз: JSON, Console и т.п. должны
	// приниматься наравне со строчными.
	c.Logging.Format = strings.ToLower(strings.TrimSpace(c.Logging.Format))
	if c.Logging.Format == "" {
		c.Logging.Format = "text"
	}
	if len(c.JWT.ClaimMappings) == 0 {
		// По умолчанию извлекаем sub как user_id
		c.JWT.ClaimMappings = []string{"sub"}
		if c.Headers.ClaimToHeader == nil {
			c.Headers.ClaimToHeader = make(map[string]string)
		}
		if _, ok := c.Headers.ClaimToHeader["sub"]; !ok {
			c.Headers.ClaimToHeader["sub"] = "X-User-ID"
		}
	}

	if c.Identity.UserLookup.CacheTTL == 0 {
		c.Identity.UserLookup.CacheTTL = 300 * time.Second
	}
	for i := range c.Identity.Providers {
		if c.Identity.Providers[i].Algorithm == "" {
			c.Identity.Providers[i].Algorithm = "HS256"
		}
		if c.Identity.Providers[i].EmailClaim == "" {
			c.Identity.Providers[i].EmailClaim = "email"
		}
		if c.Identity.Providers[i].SubjectClaim == "" {
			c.Identity.Providers[i].SubjectClaim = "sub"
		}
	}

	// Создаем правила маршрутизации из таргетов, если не заданы явно
	if len(c.Routing.Rules) == 0 {
		for _, target := range c.Targets {
			if target.PathPrefix != "" {
				c.Routing.Rules = append(c.Routing.Rules, RoutingRule{
					PathPrefix: target.PathPrefix,
					TargetName: target.Name,
					StripPath:  target.StripPrefix,
				})
			}
		}
	}

	if c.Permissions.Method == "" {
		c.Permissions.Method = defaultPermissionsMethod
	}
	if c.Permissions.Path == "" {
		c.Permissions.Path = defaultPermissionsPath
	}
	if c.Permissions.APIKeyHeader == "" {
		c.Permissions.APIKeyHeader = defaultPermissionsAPIKeyHeader
	}

	// Дефолты discovery применяются, только когда discovery включён; пустая
	// секция `discovery:` с `enabled: true` получает все значения ниже.
	if c.Discovery != nil && c.Discovery.Enabled {
		d := c.Discovery
		if d.Provider == "" {
			d.Provider = "docker"
		}
		if d.Host == "" {
			d.Host = "unix:///var/run/docker.sock"
		}
		if d.APIVersion == "" {
			d.APIVersion = "v1.41"
		}
		if d.LabelPrefix == "" {
			d.LabelPrefix = "gateway"
		}
		if len(d.ServiceNameLabels) == 0 {
			d.ServiceNameLabels = []string{
				"com.docker.compose.service",
				"io.podman.compose.service",
			}
		}
		if d.Debounce == 0 {
			d.Debounce = 500 * time.Millisecond
		}
		if d.ResyncInterval == 0 {
			d.ResyncInterval = 5 * time.Minute
		}
		if d.DefaultTimeout == 0 {
			d.DefaultTimeout = 30 * time.Second
		}
		if d.StateFile == "" {
			d.StateFile = "/var/lib/api-gateway/discovery-state.json"
		}
	}
}

// Validate проверяет корректность конфигурации (публичная обёртка для discovery).
func (c *Config) Validate() error {
	return c.validate()
}

// validHTTPMethodToken reports whether m is a non-empty HTTP method token,
// rejecting whitespace and control characters.
func validHTTPMethodToken(m string) bool {
	if m == "" {
		return false
	}
	for _, r := range m {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// validate проверяет корректность конфигурации
func (c *Config) validate() error {
	if _, err := ParseTrustedProxies(c.Server.TrustedProxies); err != nil {
		return fmt.Errorf("server.trusted_proxies: %w", err)
	}
	if c.Compression.Enabled {
		if c.Compression.Level < 1 || c.Compression.Level > 9 {
			return fmt.Errorf("compression.level must be between 1 and 9, got %d", c.Compression.Level)
		}
		if c.Compression.MinSize < 0 {
			return fmt.Errorf("compression.min_size must be >= 0, got %d", c.Compression.MinSize)
		}
	}
	if c.Admin.Enabled {
		host, _, err := net.SplitHostPort(c.Admin.Addr)
		if err != nil {
			return fmt.Errorf("admin.addr is invalid: %w", err)
		}
		if c.Admin.Token == "" {
			switch host {
			case "127.0.0.1", "::1", "localhost":
			default:
				return fmt.Errorf("admin.token is required when admin.addr is not loopback")
			}
		}
	}
	if c.HTTP3.Enabled {
		if c.TLS == nil || !c.TLS.Enabled {
			return fmt.Errorf("http3 requires tls.enabled: true")
		}
		if c.HTTP3.Port < 1 || c.HTTP3.Port > 65535 {
			return fmt.Errorf("http3.port must be between 1 and 65535, got %d", c.HTTP3.Port)
		}
	}

	discoveryEnabled := c.Discovery != nil && c.Discovery.Enabled
	if discoveryEnabled {
		switch c.Discovery.Provider {
		case "docker", "podman":
		default:
			return fmt.Errorf("discovery.provider must be docker or podman, got %q", c.Discovery.Provider)
		}
	}
	if len(c.Targets) == 0 && !discoveryEnabled {
		return fmt.Errorf("at least one target is required")
	}

	// Проверяем уникальность имен таргетов
	targetNames := make(map[string]bool)
	for _, target := range c.Targets {
		if target.Name == "" {
			return fmt.Errorf("target name is required")
		}
		if targetNames[target.Name] {
			return fmt.Errorf("duplicate target name: %s", target.Name)
		}
		targetNames[target.Name] = true

		if target.URL == "" {
			return fmt.Errorf("target.url is required for target %s", target.Name)
		}
		u, err := url.Parse(target.URL)
		if err != nil {
			return fmt.Errorf("target.url is invalid for target %s: %w", target.Name, err)
		}
		switch target.Protocol {
		case "", "h2c":
		default:
			return fmt.Errorf("target %s: protocol must be empty or h2c, got %q", target.Name, target.Protocol)
		}
		if target.Protocol == "h2c" && u.Scheme != "http" {
			return fmt.Errorf("target %s: h2c requires an http url", target.Name)
		}
		if target.TLS != nil {
			if u.Scheme != "https" {
				return fmt.Errorf("target %s: tls requires an https url", target.Name)
			}
			if (target.TLS.CertFile == "") != (target.TLS.KeyFile == "") {
				return fmt.Errorf("target %s: tls.cert_file and tls.key_file must be set together", target.Name)
			}
			if target.TLS.CAFile != "" && target.TLS.InsecureSkipVerify {
				return fmt.Errorf("target %s: tls.ca_file and tls.insecure_skip_verify are mutually exclusive", target.Name)
			}
		}
		if target.Rest != nil {
			if target.Rest.Base < 0 || target.Rest.Max < 0 {
				return fmt.Errorf("target %s: rest.base and rest.max must be non-negative", target.Name)
			}
			if target.Rest.Max > 0 && target.Rest.Max < target.Rest.EffectiveBase() {
				return fmt.Errorf("target %s: rest.max must be >= rest.base", target.Name)
			}
		}
	}

	// Проверяем правила маршрутизации
	poolPolicy := make(map[string]RoutingRule)
	for i := range c.Routing.Rules {
		rule := &c.Routing.Rules[i]
		if rule.PathRegex != "" {
			if rule.PathPrefix != "" {
				return fmt.Errorf("routing rule path_prefix and path_regex are mutually exclusive")
			}
			re, err := regexp.Compile(rule.PathRegex)
			if err != nil {
				return fmt.Errorf("routing rule path_regex %q: %w", rule.PathRegex, err)
			}
			rule.pathRe = re
		} else if rule.PathPrefix == "" {
			return fmt.Errorf("routing rule path_prefix is required")
		}
		if !targetNames[rule.TargetName] {
			return fmt.Errorf("routing rule references unknown target: %s", rule.TargetName)
		}
		switch rule.LBPolicy {
		case "", "round_robin", "random", "least_conn", "ip_hash", "sticky":
		default:
			return fmt.Errorf("routing rule lb_policy must be round_robin, random, least_conn, ip_hash or sticky, got %q", rule.LBPolicy)
		}
		if rule.Retries < 0 || rule.Retries > 5 {
			return fmt.Errorf("routing rule retries must be between 0 and 5, got %d", rule.Retries)
		}
		// Правила, совпадающие по (host, path_prefix, methods), делят один пул
		// балансировки. Политика пула (auth, strip_path, rate_limit) должна
		// совпадать, иначе поведение запроса зависело бы от выбранного таргета.
		key := RuleRouteKey(*rule)
		if first, ok := poolPolicy[key]; ok {
			if first.StripPath != rule.StripPath ||
				!reflect.DeepEqual(first.Auth, rule.Auth) ||
				!reflect.DeepEqual(first.RateLimit, rule.RateLimit) {
				return fmt.Errorf("routing rules for host %q path_prefix %q methods %v share a target pool but differ in auth, strip_path or rate_limit",
					rule.Host, rule.PathPrefix, rule.Methods)
			}
			continue
		}
		poolPolicy[key] = *rule
	}

	// Проверяем формат логирования. Пустое значение допустимо для
	// программно собранных конфигов — setDefaults подставляет "text".
	// Нормализуем регистр, чтобы "JSON"/"Console" принимались и сохранялись
	// в каноническом виде.
	format := strings.ToLower(strings.TrimSpace(c.Logging.Format))
	if format != "" {
		switch format {
		case "console", "text", "json":
			c.Logging.Format = format
		default:
			return fmt.Errorf("logging.format must be one of console, text, json, got %q", c.Logging.Format)
		}
	}

	// Проверяем TLS конфигурацию
	if c.TLS != nil && c.TLS.Enabled {
		if len(c.TLS.Domains) == 0 {
			return fmt.Errorf("at least one domain is required when TLS is enabled")
		}
		hasWildcard := false
		for _, domain := range c.TLS.Domains {
			if !strings.Contains(domain, "*") {
				continue
			}
			if !strings.HasPrefix(domain, "*.") || strings.Count(domain, ".") < 2 {
				return fmt.Errorf("tls.domains: unsupported wildcard %q, want *.example.com", domain)
			}
			hasWildcard = true
		}
		hasWildcardFiles := c.TLS.WildcardCertFile != "" || c.TLS.WildcardKeyFile != ""
		if (c.TLS.WildcardCertFile == "") != (c.TLS.WildcardKeyFile == "") {
			return fmt.Errorf("tls.wildcard_cert_file and tls.wildcard_key_file must be set together")
		}
		if hasWildcardFiles && !hasWildcard {
			return fmt.Errorf("tls.wildcard_cert_file requires at least one wildcard domain in tls.domains")
		}
		if hasWildcard && c.TLS.DNSProvider == "" && !hasWildcardFiles {
			return fmt.Errorf("tls.domains: wildcard requires tls.dns_provider (DNS-01) or tls.wildcard_cert_file/tls.wildcard_key_file")
		}
		if c.TLS.DNSProvider != "" {
			if c.TLS.DNSProvider == "regru" && (c.TLS.DNSUsername == "" || c.TLS.DNSPassword == "") {
				return fmt.Errorf("tls.dns_username and tls.dns_password are required for dns_provider regru")
			}
			if !hasWildcard {
				return fmt.Errorf("tls.dns_provider requires at least one wildcard domain in tls.domains")
			}
			if c.TLS.DNSPropagationTimeout < 0 {
				return fmt.Errorf("tls.dns_propagation_timeout must be >= 0")
			}
		}
		if _, err := ParseTLSVersion(c.TLS.MinVersion); err != nil {
			return fmt.Errorf("tls.min_version: %w", err)
		}
		if _, err := ParseCipherSuites(c.TLS.CipherSuites); err != nil {
			return fmt.Errorf("tls.cipher_suites: %w", err)
		}
		if _, err := ParseCurves(c.TLS.Curves); err != nil {
			return fmt.Errorf("tls.curves: %w", err)
		}
		clientAuth, err := ParseClientAuth(c.TLS.ClientAuth)
		if err != nil {
			return fmt.Errorf("tls.client_auth: %w", err)
		}
		if clientAuth == tls.RequireAndVerifyClientCert && strings.TrimSpace(c.TLS.ClientCAFile) == "" {
			return fmt.Errorf("tls.client_ca_file is required when tls.client_auth is verify")
		}
		if strings.TrimSpace(c.TLS.ClientCAFile) != "" {
			if _, err := LoadClientCAPool(c.TLS.ClientCAFile); err != nil {
				return fmt.Errorf("invalid tls.client_ca_file: %w", err)
			}
		}
		if c.TLS.Email == "" {
			return fmt.Errorf("email is required for Let's Encrypt registration")
		}
		if c.TLS.WorkerPort != 0 {
			if c.TLS.WorkerPort < 0 {
				return fmt.Errorf("tls.worker_port must be positive or 0 (disabled), got %d", c.TLS.WorkerPort)
			}
			if c.TLS.WorkerPort == c.TLS.Port || c.TLS.WorkerPort == c.TLS.HTTPPort {
				return fmt.Errorf("tls.worker_port %d conflicts with tls.port %d or tls.http_port %d",
					c.TLS.WorkerPort, c.TLS.Port, c.TLS.HTTPPort)
			}
			if strings.TrimSpace(c.TLS.WorkerClientCAFile) == "" {
				return fmt.Errorf("tls.worker_client_ca_file is required when tls.worker_port is set")
			}
			if _, err := LoadClientCAPool(c.TLS.WorkerClientCAFile); err != nil {
				return fmt.Errorf("invalid tls.worker_client_ca_file: %w", err)
			}
		}
	} else if c.TLS != nil && c.TLS.WorkerPort != 0 {
		return fmt.Errorf("tls.worker_port requires tls.enabled: true")
	}

	// Проверяем JWT конфигурацию
	if c.JWT.Required {
		c.JWT.ValidateExp = true
	}

	if c.Permissions.CacheTTL == 0 {
		c.Permissions.CacheTTL = 300 * time.Second
	}
	if c.Permissions.HeaderName == "" {
		c.Permissions.HeaderName = "X-User-Permissions"
	}
	if c.Permissions.InvalidateToken == "" && c.Permissions.APIKey != "" {
		c.Permissions.InvalidateToken = c.Permissions.APIKey
	}

	if c.Permissions.Enabled {
		if c.Permissions.ServiceURL == "" {
			return fmt.Errorf("permissions.service_url is required when permissions.enabled is true")
		}
		if !strings.Contains(c.Permissions.Path, "{user_id}") {
			return fmt.Errorf("permissions.path must contain the {user_id} placeholder, got %q", c.Permissions.Path)
		}
		if !validHTTPMethodToken(c.Permissions.Method) {
			return fmt.Errorf("permissions.method must be a non-empty HTTP token without whitespace or control characters, got %q", c.Permissions.Method)
		}
	}

	for _, wh := range c.Webhooks {
		if wh.Name == "" {
			return fmt.Errorf("webhook name is required")
		}
		if wh.Transport == "" {
			return fmt.Errorf("webhook %s: transport is required", wh.Name)
		}
		if wh.Transport == TransportNATS && wh.NATSURL == "" {
			return fmt.Errorf("webhook %s: nats_url is required for nats transport", wh.Name)
		}
		if wh.Transport == TransportNATS && wh.Subject == "" {
			return fmt.Errorf("webhook %s: subject is required for nats transport", wh.Name)
		}
		if wh.Transport == TransportWebhook && wh.WebhookURL == "" {
			return fmt.Errorf("webhook %s: webhook_url is required for webhook transport", wh.Name)
		}
		if wh.Trigger == "" {
			return fmt.Errorf("webhook %s: trigger is required (on_request|on_response)", wh.Name)
		}
	}

	if c.Identity.Enabled {
		if len(c.Identity.Providers) == 0 {
			return fmt.Errorf("identity.enabled requires at least one provider")
		}
		names := make(map[string]bool, len(c.Identity.Providers))
		for i := range c.Identity.Providers {
			p := &c.Identity.Providers[i]
			if p.Name == "" {
				return fmt.Errorf("identity provider name is required")
			}
			if names[p.Name] {
				return fmt.Errorf("duplicate identity provider name: %s", p.Name)
			}
			names[p.Name] = true
			if len(p.Algorithm) < 2 {
				return fmt.Errorf("identity provider %s: invalid algorithm %q", p.Name, p.Algorithm)
			}
			algPrefix := strings.ToUpper(p.Algorithm[:2])
			// jwks_url — только для асимметричных RS*/ES*: по JWK-набору
			// нельзя проверить HMAC-подпись (секрет не публикуется).
			if p.JwksURL != "" && algPrefix != "RS" && algPrefix != "ES" {
				return fmt.Errorf("identity provider %s: jwks_url requires RS* or ES* algorithm", p.Name)
			}
			// Инвариант разделения секретов: партнёрский HMAC-секрет не должен
			// совпадать с нашими, иначе партнёрский токен прошёл бы как наш.
			if algPrefix == "HS" {
				if p.SecretKey == "" {
					return fmt.Errorf("identity provider %s: secret_key is required for HS* algorithm", p.Name)
				}
				if p.SecretKey == c.JWT.SecretKey {
					return fmt.Errorf("identity provider %s: secret_key must differ from jwt.secret_key", p.Name)
				}
				if p.SecretKey == c.Permissions.APIKey {
					return fmt.Errorf("identity provider %s: secret_key must differ from permissions.api_key", p.Name)
				}
			}
		}
		if c.Identity.UserLookup.ServiceURL == "" {
			return fmt.Errorf("identity.user_lookup.service_url is required when identity.enabled is true")
		}
	}

	return nil
}

// normalizeRequestHost отбрасывает порт из заголовка Host. Для IPv6
// возвращает адрес без скобок, чтобы правила можно было задавать как ::1.
func normalizeRequestHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// Обычный случай — имя хоста без порта. Без этой проверки
	// net.SplitHostPort создаёт *AddrError на каждом запросе.
	if !strings.Contains(host, ":") {
		return host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(h, "[]")
	}
	return host
}

// GetTargetByName возвращает таргет по имени
func (c *Config) GetTargetByName(name string) *TargetConfig {
	for i := range c.Targets {
		if c.Targets[i].Name == name {
			return &c.Targets[i]
		}
	}
	return nil
}

// FindTargetForPath находит таргет по пути. Правила с headers/query при
// таком вызове не совпадают: без запроса их проверить нельзя. Для реального
// трафика используйте FindTargetForRequest.
func (c *Config) FindTargetForPath(path string, method string, host ...string) (*TargetConfig, *RoutingRule) {
	reqHost := ""
	if len(host) > 0 {
		reqHost = host[0]
	}
	return c.findTarget(path, method, reqHost, nil, nil)
}

// FindTargetForRequest находит таргет с учётом всех матчеров правила:
// host, methods, headers, query и path_prefix/path_regex.
func (c *Config) FindTargetForRequest(r *http.Request) (*TargetConfig, *RoutingRule) {
	return c.findTarget(r.URL.Path, r.Method, r.Host, r.Header, r.URL)
}

// findTarget — общий матчер. Query парсится только если до него дошла
// проверка правила с query-матчерами: конфиги без таких правил не платят
// за r.URL.Query() на каждом запросе. u == nil у путей без запроса.
func (c *Config) findTarget(path, method, host string, header http.Header, u *url.URL) (*TargetConfig, *RoutingRule) {
	var (
		query       url.Values
		queryParsed bool
	)
	var bestMatch *RoutingRule
	bestScore := -1

	// Порт в Host не участвует в правилах: воркеры ходят на
	// https://tracker.sarnas.ru:8444 и присылают Host с портом, а
	// правила заданы именами хостов.
	reqHost := normalizeRequestHost(host)

	for i := range c.Routing.Rules {
		rule := &c.Routing.Rules[i]

		if rule.Host != "" {
			if reqHost == "" {
				continue
			}
			// Wildcard host: *.example.com
			if strings.HasPrefix(rule.Host, "*.") {
				suffix := rule.Host[1:] // .example.com
				if !strings.HasSuffix(reqHost, suffix) {
					continue
				}
			} else if !strings.EqualFold(reqHost, rule.Host) {
				continue
			}
		}

		if len(rule.Methods) > 0 {
			methodAllowed := false
			for _, m := range rule.Methods {
				if strings.EqualFold(m, method) {
					methodAllowed = true
					break
				}
			}
			if !methodAllowed {
				continue
			}
		}

		if !headerMatches(rule.Headers, header) {
			continue
		}
		if len(rule.Query) > 0 {
			if u == nil {
				continue
			}
			if !queryParsed {
				query = u.Query()
				queryParsed = true
			}
			if !queryMatches(rule.Query, query) {
				continue
			}
		}

		if rule.PathRegex != "" {
			re := rule.pathRe
			if re == nil {
				// Конфиг не проходил Validate (например, собран в тесте):
				// компилируем на месте один раз, без записи в правило.
				if re, _ = regexp.Compile(rule.PathRegex); re == nil {
					continue
				}
			}
			if !re.MatchString(path) {
				continue
			}
		} else if !strings.HasPrefix(path, rule.PathPrefix) {
			continue
		}

		if score := rule.matchScore(); bestMatch == nil || score > bestScore {
			bestMatch = rule
			bestScore = score
		}
	}

	if bestMatch != nil {
		return c.GetTargetByName(bestMatch.TargetName), bestMatch
	}

	return nil, nil
}

// matchScore — приоритет правила: host, затем число header/query-матчеров,
// затем regex, затем длина path_prefix. Без новых матчеров поведение
// прежнее: длинный префикс > короткий, host > без host при равном префиксе.
func (r *RoutingRule) matchScore() int {
	prefix := len(r.PathPrefix)
	if prefix > 1<<14-1 {
		prefix = 1<<14 - 1
	}
	score := prefix
	if r.PathRegex != "" {
		score += 1 << 15
	}
	score += (len(r.Headers) + len(r.Query)) << 16
	if r.Host != "" {
		score += 1 << 24
	}
	return score
}

// headerMatches проверяет все header-матчеры. Пустое ожидаемое значение —
// «заголовок присутствует» (любое значение). Отсутствие header-матчеров
// совпадает всегда, в том числе когда запрос без заголовков.
func headerMatches(want map[string]string, header http.Header) bool {
	if len(want) == 0 {
		return true
	}
	if header == nil {
		return false
	}
	for name, value := range want {
		vals, ok := header[http.CanonicalHeaderKey(name)]
		if !ok || len(vals) == 0 {
			return false
		}
		if value != "" && vals[0] != value {
			return false
		}
	}
	return true
}

// queryMatches проверяет все query-матчеры. Пустое ожидаемое значение —
// «параметр присутствует».
func queryMatches(want map[string]string, q url.Values) bool {
	if len(want) == 0 {
		return true
	}
	for name, value := range want {
		vals, ok := q[name]
		if !ok || len(vals) == 0 {
			return false
		}
		if value != "" && vals[0] != value {
			return false
		}
	}
	return true
}
