package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// writeTestCACert создаёт self-signed CA в PEM во временном каталоге теста.
// Сертификаты не коммитятся — только для проверки загрузки CA.
func writeTestCACert(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-worker-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "worker-ca.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestLoad_ValidConfig(t *testing.T) {
	yaml := `
server:
  port: 9090
application:
  env: "dev"
targets:
  - name: "test-api"
    url: "http://localhost:9001"
    timeout: 10s
    path_prefix: "/api/v1/test"
jwt:
  secret_key: "my-secret"
  algorithm: "HS256"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Server.Port)
	}
	if cfg.Targets[0].Timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", cfg.Targets[0].Timeout)
	}
}

func TestLoad_DefaultsTargetWeightToOne(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Targets[0].EffectiveWeight() != 1 {
		t.Errorf("target weight = %d, want default 1", cfg.Targets[0].EffectiveWeight())
	}
	if cfg.Targets[0].Weight == nil || *cfg.Targets[0].Weight != 1 {
		t.Errorf("omitted weight must default to 1, got %v", cfg.Targets[0].Weight)
	}
}

func TestLoad_ExplicitZeroWeightIsExcluded(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
    weight: 0
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Targets[0].Weight == nil || *cfg.Targets[0].Weight != 0 {
		t.Fatalf("explicit weight 0 must be preserved, got %v", cfg.Targets[0].Weight)
	}
	if cfg.Targets[0].EffectiveWeight() != 0 {
		t.Errorf("explicit weight 0 effective = %d, want 0 (excluded)", cfg.Targets[0].EffectiveWeight())
	}
}

func TestLoad_MissingTarget(t *testing.T) {
	yaml := `
server:
  port: 8080
targets: []
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty targets")
	}
}

func TestLoad_DuplicateTargetName(t *testing.T) {
	yaml := `
targets:
  - name: "dup"
    url: "http://localhost:9001"
  - name: "dup"
    url: "http://localhost:9002"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate target name")
	}
}

func TestLoad_IgnoresRemovedForwardHeaders(t *testing.T) {
	// headers.forward_headers удалён: заголовки проксируются всегда. Старый
	// конфиг с этим ключом должен по-прежнему загружаться (ключ игнорируется
	// как неизвестный), а не падать.
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
headers:
  forward_headers: true
  strip_authorization: true
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("config with removed headers.forward_headers must still load: %v", err)
	}
	if !cfg.Headers.StripAuthorization {
		t.Error("sibling headers settings must still be parsed")
	}
}

func TestLoad_RejectsMalformedTargetURL(t *testing.T) {
	yaml := `
targets:
  - name: "bad"
    url: "http://[::1"
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected error for malformed target URL")
	}
}

func TestFindTargetForPath_LongestPrefix(t *testing.T) {
	yaml := `
targets:
  - name: "auth"
    url: "http://auth:9001"
    path_prefix: "/api/v1/auth"
  - name: "auth-login"
    url: "http://auth:9001"
    path_prefix: "/api/v1/auth/login"
routing:
  rules:
    - path_prefix: "/api/v1/auth/login"
      target_name: "auth-login"
    - path_prefix: "/api/v1/auth"
      target_name: "auth"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	target, _ := cfg.FindTargetForPath("/api/v1/auth/login", "GET")
	if target == nil || target.Name != "auth-login" {
		t.Errorf("expected auth-login, got %v", target)
	}

	target, _ = cfg.FindTargetForPath("/api/v1/auth/register", "GET")
	if target == nil || target.Name != "auth" {
		t.Errorf("expected auth, got %v", target)
	}
}

func TestFindTargetForPath_HostBeatsHostlessOnEqualPrefix(t *testing.T) {
	yaml := `
targets:
  - name: "frontend"
    url: "http://frontend:3000"
    path_prefix: "/"
  - name: "chatcom"
    url: "http://chatcom:8086"
    path_prefix: "/"
routing:
  rules:
    - path_prefix: "/"
      target_name: "frontend"
    - host: "chatcom.online"
      path_prefix: "/"
      target_name: "chatcom"
`
	cfg, _, err := Load(writeTempConfig(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	if tg, _ := cfg.FindTargetForPath("/", "GET", "chatcom.online"); tg == nil || tg.Name != "chatcom" {
		t.Errorf("chatcom.online: expected chatcom, got %v", tg)
	}
	if tg, _ := cfg.FindTargetForPath("/", "GET", "sarnas.ru"); tg == nil || tg.Name != "frontend" {
		t.Errorf("sarnas.ru: expected frontend, got %v", tg)
	}
}

func TestFindTargetForPath_HonorsMethods(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
    path_prefix: "/api"
routing:
  rules:
    - path_prefix: "/api"
      target_name: "api"
      methods: ["GET"]
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	_, rule := cfg.FindTargetForPath("/api/test", "POST")
	if rule != nil {
		t.Errorf("expected no match for POST, but got rule: %+v", rule)
	}

	target, rule := cfg.FindTargetForPath("/api/test", "GET")
	if target == nil || rule == nil {
		t.Errorf("expected match for GET")
	}
}

func TestConfig_Defaults(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("default port should be 8080, got %d", cfg.Server.Port)
	}
	if cfg.JWT.Algorithm != "HS256" {
		t.Errorf("default algorithm should be HS256, got %s", cfg.JWT.Algorithm)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("default log level should be info, got %s", cfg.Logging.Level)
	}
}

func TestHTTP3DefaultsAndValidation(t *testing.T) {
	base := `
targets:
  - name: api
    url: http://api:9001
%s
`
	path := writeTempConfig(t, fmt.Sprintf(base, `
tls:
  enabled: true
  domains: ["api.example.com"]
  email: "admin@example.com"
http3:
  enabled: true
`))
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP3.Port != 443 {
		t.Fatalf("http3 port = %d, want 443", cfg.HTTP3.Port)
	}

	if _, _, err := Load(writeTempConfig(t, fmt.Sprintf(base, "http3:\n  enabled: true"))); err == nil {
		t.Fatal("http3 without tls must be rejected")
	}
	if _, _, err := Load(writeTempConfig(t, fmt.Sprintf(base, `
tls:
  enabled: true
  domains: ["api.example.com"]
  email: "admin@example.com"
http3:
  enabled: true
  port: 70000
`))); err == nil {
		t.Fatal("invalid http3 port must be rejected")
	}
}

func TestRouting_LBPolicyValidation(t *testing.T) {
	base := `
targets:
  - name: api
    url: http://api:9001
routing:
  rules:
    - path_prefix: "/"
      target_name: api
%s
`
	for _, extra := range []string{
		"      lb_policy: bogus",
		"      retries: -1",
		"      retries: 6",
	} {
		path := writeTempConfig(t, fmt.Sprintf(base, extra))
		if _, _, err := Load(path); err == nil {
			t.Fatalf("expected error for %q", extra)
		}
	}
	for _, policy := range []string{"ip_hash", "sticky"} {
		path := writeTempConfig(t, fmt.Sprintf(base, "      lb_policy: "+policy+"\n      retries: 2"))
		if _, _, err := Load(path); err != nil {
			t.Fatalf("%s: %v", policy, err)
		}
	}
}

func TestPluginsConfig(t *testing.T) {
	yaml := `
targets:
  - name: api
    url: http://api:9001
plugins:
  example:
    header: "X-Tenant"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Plugins["example"]["header"] != "X-Tenant" {
		t.Fatalf("plugins = %v", cfg.Plugins)
	}
}

func TestAdmin_DefaultsAndValidation(t *testing.T) {
	base := `
targets:
  - name: api
    url: http://api:9001
admin:
%s
`
	path := writeTempConfig(t, fmt.Sprintf(base, "  enabled: true"))
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Admin.Addr != "127.0.0.1:2019" {
		t.Fatalf("admin addr = %q", cfg.Admin.Addr)
	}

	for _, extra := range []string{
		"  enabled: true\n  addr: \"0.0.0.0:2019\"",
		"  enabled: true\n  addr: \"bad\"",
	} {
		path := writeTempConfig(t, fmt.Sprintf(base, extra))
		if _, _, err := Load(path); err == nil {
			t.Fatalf("expected error for admin config %q", extra)
		}
	}

	path = writeTempConfig(t, fmt.Sprintf(base, "  enabled: true\n  addr: \"0.0.0.0:2019\"\n  token: \"secret\""))
	if _, _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestCompression_DefaultsAndValidation(t *testing.T) {
	base := `
targets:
  - name: api
    url: http://api:9001
compression:
%s
`
	path := writeTempConfig(t, fmt.Sprintf(base, "  enabled: true\n  level: 0\n  min_size: 0"))
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Compression.Level != 5 {
		t.Errorf("default compression level = %d, want 5", cfg.Compression.Level)
	}
	if cfg.Compression.MinSize != 1024 {
		t.Errorf("default compression min_size = %d, want 1024", cfg.Compression.MinSize)
	}

	path = writeTempConfig(t, fmt.Sprintf(base, "  enabled: true\n  level: 99"))
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected error for compression level outside 1..9")
	}
}

func TestValidate_TrustedProxies(t *testing.T) {
	base := `
targets:
  - name: api
    url: http://api:9001
server:
  trusted_proxies: [%s]
`
	for _, tc := range []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"cidr", `"10.0.0.0/8"`, false},
		{"exact ipv4", `"10.0.0.5"`, false},
		{"exact ipv6", `"2001:db8::1"`, false},
		{"garbage", `"not-an-ip"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempConfig(t, fmt.Sprintf(base, tc.value))
			_, _, err := Load(path)
			if tc.wantErr && err == nil {
				t.Fatal("expected error for invalid trusted proxy")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestTLS_ValidConfig(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains:
    - "api.example.com"
  email: "admin@example.com"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TLS.Enabled {
		t.Fatal("expected TLS enabled")
	}
	if cfg.TLS.Port != 443 {
		t.Errorf("default TLS port should be 443, got %d", cfg.TLS.Port)
	}
	if cfg.TLS.CacheDir != "/var/lib/api-gateway/certs" {
		t.Errorf("default cache dir mismatch, got %s", cfg.TLS.CacheDir)
	}
}

func TestTLS_NoDomains(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  email: "admin@example.com"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for TLS without domains")
	}
}

func TestTLS_WildcardDomainRejected(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains:
    - "*.example.com"
  email: "admin@example.com"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for wildcard TLS domain")
	}
	if !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("error must explain wildcard limitation, got: %v", err)
	}
}

func TestTLSPolicyParsers(t *testing.T) {
	if v, err := ParseTLSVersion("1.3"); err != nil || v != tls.VersionTLS13 {
		t.Fatalf("ParseTLSVersion = %x, %v", v, err)
	}
	if _, err := ParseTLSVersion("1.1"); err == nil {
		t.Fatal("TLS 1.1 must be rejected")
	}
	if suites, err := ParseCipherSuites([]string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}); err != nil || len(suites) != 1 {
		t.Fatalf("ParseCipherSuites = %v, %v", suites, err)
	}
	if _, err := ParseCipherSuites([]string{"TLS_AES_128_GCM_SHA256"}); err == nil {
		t.Fatal("TLS 1.3 cipher suite must be rejected as non-configurable")
	}
	if curves, err := ParseCurves([]string{"X25519", "P-256"}); err != nil || len(curves) != 2 {
		t.Fatalf("ParseCurves = %v, %v", curves, err)
	}
	if _, err := ParseClientAuth("bogus"); err == nil {
		t.Fatal("bogus client_auth must be rejected")
	}
}

func TestTLS_PolicyValidation(t *testing.T) {
	base := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains: ["api.example.com"]
  email: "admin@example.com"
%s
`
	cases := []string{
		"  min_version: \"1.1\"",
		"  cipher_suites: [\"NOPE\"]",
		"  curves: [\"NOPE\"]",
		"  client_auth: \"bogus\"",
		"  client_auth: \"verify\"",
	}
	for _, extra := range cases {
		path := writeTempConfig(t, fmt.Sprintf(base, extra))
		if _, _, err := Load(path); err == nil {
			t.Fatalf("expected validation error for %q", extra)
		}
	}
}

func TestTLS_WildcardWithDNSProviderAccepted(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains:
    - "example.com"
    - "*.example.com"
  email: "admin@example.com"
  dns_provider: "regru"
  dns_username: "user"
  dns_password: "pass"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.DNSProvider != "regru" {
		t.Fatalf("dns_provider = %q", cfg.TLS.DNSProvider)
	}
}

func TestTLS_WildcardWithCertFilesAccepted(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains: ["*.example.com"]
  email: "admin@example.com"
  wildcard_cert_file: "/etc/letsencrypt/live/example.com/fullchain.pem"
  wildcard_key_file: "/etc/letsencrypt/live/example.com/privkey.pem"
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err != nil {
		t.Fatal(err)
	}
}

func TestTLS_WildcardCertFilesMustBePair(t *testing.T) {
	base := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains: ["*.example.com"]
  email: "admin@example.com"
%s
`
	for _, extra := range []string{
		"  wildcard_cert_file: \"/tmp/cert.pem\"",
		"  wildcard_key_file: \"/tmp/key.pem\"",
	} {
		path := writeTempConfig(t, fmt.Sprintf(base, extra))
		if _, _, err := Load(path); err == nil {
			t.Fatalf("expected error for %q without the pair", extra)
		}
	}
}

func TestTLS_DNSProviderValidation(t *testing.T) {
	base := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  email: "admin@example.com"
%s
`
	cases := []struct {
		name  string
		extra string
	}{
		{"missing credentials", "  domains: [\"*.example.com\"]\n  dns_provider: regru"},
		{"provider without wildcard", "  domains: [example.com]\n  dns_provider: regru\n  dns_username: u\n  dns_password: p"},
		{"negative propagation", "  domains: [\"*.example.com\"]\n  dns_provider: regru\n  dns_username: u\n  dns_password: p\n  dns_propagation_timeout: -1s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempConfig(t, fmt.Sprintf(base, tc.extra))
			if _, _, err := Load(path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestTLS_ExternalDNSProviderAccepted(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains: ["*.example.com"]
  email: "admin@example.com"
  dns_provider: "cloudflare"
  dns_config:
    api_token: "token"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.DNSConfig["api_token"] != "token" {
		t.Fatalf("dns_config = %v", cfg.TLS.DNSConfig)
	}
}

func TestTLS_NoEmail(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains:
    - "api.example.com"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for TLS without email")
	}
}

func TestTLS_WorkerListenerDisabledByDefault(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains:
    - "api.example.com"
  email: "admin@example.com"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TLS.WorkerPort != 0 {
		t.Errorf("worker_port default = %d, want 0 (disabled)", cfg.TLS.WorkerPort)
	}
}

func TestTLS_WorkerListenerValidConfig(t *testing.T) {
	caFile := writeTestCACert(t)
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains:
    - "api.example.com"
  email: "admin@example.com"
  worker_port: 8444
  worker_client_ca_file: "` + caFile + `"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TLS.WorkerPort != 8444 {
		t.Errorf("worker_port = %d, want 8444", cfg.TLS.WorkerPort)
	}
	if cfg.TLS.WorkerClientCAFile != caFile {
		t.Errorf("worker_client_ca_file = %q, want %q", cfg.TLS.WorkerClientCAFile, caFile)
	}
}

func TestTLS_WorkerListenerRequiresCA(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains:
    - "api.example.com"
  email: "admin@example.com"
  worker_port: 8444
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for worker_port without worker_client_ca_file")
	}
	if !strings.Contains(err.Error(), "worker_client_ca_file") {
		t.Errorf("error should name worker_client_ca_file, got %v", err)
	}
}

func TestTLS_WorkerListenerRejectsUnreadableCA(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains:
    - "api.example.com"
  email: "admin@example.com"
  worker_port: 8444
  worker_client_ca_file: "/nonexistent/worker-ca.pem"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unreadable worker_client_ca_file")
	}
	if !strings.Contains(err.Error(), "worker_client_ca_file") {
		t.Errorf("error should name worker_client_ca_file, got %v", err)
	}
}

func TestTLS_WorkerListenerRejectsNonPEMCA(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "not-a-ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  domains:
    - "api.example.com"
  email: "admin@example.com"
  worker_port: 8444
  worker_client_ca_file: "` + notPEM + `"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for non-PEM worker_client_ca_file")
	}
}

func TestTLS_WorkerListenerRequiresTLSEnabled(t *testing.T) {
	caFile := writeTestCACert(t)
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: false
  worker_port: 8444
  worker_client_ca_file: "` + caFile + `"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for worker_port with TLS disabled")
	}
}

func TestTLS_WorkerListenerRejectsPortConflict(t *testing.T) {
	caFile := writeTestCACert(t)
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
tls:
  enabled: true
  port: 8444
  domains:
    - "api.example.com"
  email: "admin@example.com"
  worker_port: 8444
  worker_client_ca_file: "` + caFile + `"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for worker_port equal to tls.port")
	}
}

func TestLoadClientCAPool(t *testing.T) {
	caFile := writeTestCACert(t)
	pool, err := LoadClientCAPool(caFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pool == nil {
		t.Fatal("expected CA pool")
	}

	// Пул действительно принимает сертификат из файла как доверенный корень.
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block in CA file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("pool does not trust the CA from the file: %v", err)
	}

	if _, err := LoadClientCAPool(""); err == nil {
		t.Error("expected error for empty path")
	}
	if _, err := LoadClientCAPool(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestDiscovery_DefaultsApplied(t *testing.T) {
	yaml := `
discovery:
  enabled: true
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d := cfg.Discovery
	if d == nil || !d.Enabled {
		t.Fatal("discovery should be enabled")
	}
	if d.Provider != "docker" {
		t.Errorf("provider default: got %q", d.Provider)
	}
	if d.Host != "unix:///var/run/docker.sock" {
		t.Errorf("host default: got %q", d.Host)
	}
	if d.APIVersion != "v1.41" {
		t.Errorf("api_version default: got %q", d.APIVersion)
	}
	if d.LabelPrefix != "gateway" {
		t.Errorf("label_prefix default: got %q", d.LabelPrefix)
	}
	if len(d.ServiceNameLabels) != 2 ||
		d.ServiceNameLabels[0] != "com.docker.compose.service" ||
		d.ServiceNameLabels[1] != "io.podman.compose.service" {
		t.Errorf("service_name_labels default: got %v", d.ServiceNameLabels)
	}
	if d.Debounce != 500*time.Millisecond {
		t.Errorf("debounce default: got %v", d.Debounce)
	}
	if d.ResyncInterval != 5*time.Minute {
		t.Errorf("resync default: got %v", d.ResyncInterval)
	}
	if d.DefaultTimeout != 30*time.Second {
		t.Errorf("default_timeout default: got %v", d.DefaultTimeout)
	}
}

func TestDiscovery_AllowsEmptyTargetsWhenEnabled(t *testing.T) {
	yaml := `
targets: []
discovery:
  enabled: true
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("empty targets must be allowed with discovery enabled: %v", err)
	}
	if len(cfg.Targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(cfg.Targets))
	}
}

func TestDiscovery_StillRequiresTargetsWhenDisabled(t *testing.T) {
	yaml := `
targets: []
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected error for empty targets without discovery")
	}
}

func TestDiscovery_InvalidProvider(t *testing.T) {
	yaml := `
targets: []
discovery:
  enabled: true
  provider: nomad
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestDiscovery_PodmanProviderAccepted(t *testing.T) {
	yaml := `
targets: []
discovery:
  enabled: true
  provider: podman
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err != nil {
		t.Fatalf("podman provider must be accepted: %v", err)
	}
}

func TestConfig_MaxIdleConnsPerHostDefault(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxIdleConnsPerHost != 1000 {
		t.Errorf("default max_idle_conns_per_host = %d, want 1000", cfg.MaxIdleConnsPerHost)
	}
}

func TestConfig_MaxIdleConnsPerHostOverride(t *testing.T) {
	yaml := `
application:
  max_idle_conns_per_host: 250
targets:
  - name: "api"
    url: "http://api:9001"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxIdleConnsPerHost != 250 {
		t.Errorf("max_idle_conns_per_host = %d, want 250", cfg.MaxIdleConnsPerHost)
	}
}

func TestLoad_LoggingFormatAccepted(t *testing.T) {
	for _, format := range []string{"console", "text", "json"} {
		t.Run(format, func(t *testing.T) {
			yaml := "targets:\n  - name: \"api\"\n    url: \"http://api:9001\"\nlogging:\n  format: \"" + format + "\"\n"
			path := writeTempConfig(t, yaml)
			if _, _, err := Load(path); err != nil {
				t.Fatalf("logging.format %q must be accepted: %v", format, err)
			}
		})
	}
}

func TestLoad_LoggingFormatCaseInsensitive(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"JSON", "json"},
		{"Console", "console"},
		{"TEXT", "text"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			yaml := "targets:\n  - name: \"api\"\n    url: \"http://api:9001\"\nlogging:\n  format: \"" + tc.in + "\"\n"
			path := writeTempConfig(t, yaml)
			cfg, _, err := Load(path)
			if err != nil {
				t.Fatalf("logging.format %q must be accepted case-insensitively: %v", tc.in, err)
			}
			if cfg.Logging.Format != tc.want {
				t.Errorf("logging.format %q normalized = %q, want %q", tc.in, cfg.Logging.Format, tc.want)
			}
		})
	}
}

func TestLoad_RejectsUnknownLoggingFormat(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
logging:
  format: "xml"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown logging.format")
	}
	if !strings.Contains(err.Error(), "logging.format") || !strings.Contains(err.Error(), "xml") {
		t.Errorf("error must name the field and value, got: %v", err)
	}
}

func TestLoad_RejectsPooledRulesWithDifferentPolicy(t *testing.T) {
	const header = `
targets:
  - name: a
    url: http://a:9000
  - name: b
    url: http://b:9000
routing:
  rules:
`
	cases := []struct {
		name  string
		ruleA string
		ruleB string
	}{
		{
			name:  "auth differs",
			ruleA: "    - {host: h, path_prefix: /api, target_name: a, auth: {required: true}}\n",
			ruleB: "    - {host: h, path_prefix: /api, target_name: b, auth: {required: false}}\n",
		},
		{
			name:  "strip_path differs",
			ruleA: "    - {host: h, path_prefix: /api, target_name: a}\n",
			ruleB: "    - {host: h, path_prefix: /api, target_name: b, strip_path: true}\n",
		},
		{
			name:  "rate_limit differs",
			ruleA: "    - {host: h, path_prefix: /api, target_name: a}\n",
			ruleB: "    - {host: h, path_prefix: /api, target_name: b, rate_limit: {requests_per_second: 10, burst: 20}}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempConfig(t, header+tc.ruleA+tc.ruleB)
			_, _, err := Load(path)
			if err == nil {
				t.Fatal("expected error for pooled rules with differing policy")
			}
			if !strings.Contains(err.Error(), "pool") {
				t.Errorf("error should explain the shared pool conflict, got: %v", err)
			}
		})
	}
}

func TestLoad_AcceptsPooledRulesWithIdenticalPolicy(t *testing.T) {
	yaml := `
targets:
  - name: a
    url: http://a:9000
  - name: b
    url: http://b:9000
routing:
  rules:
    - {host: h, path_prefix: /api, target_name: a, strip_path: true, auth: {required: true}, rate_limit: {requests_per_second: 10, burst: 20}}
    - {host: h, path_prefix: /api, target_name: b, strip_path: true, auth: {required: true}, rate_limit: {requests_per_second: 10, burst: 20}}
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("pooled rules with identical policy must load: %v", err)
	}
	if len(cfg.Routing.Rules) != 2 {
		t.Fatalf("both pooled rules must survive, got %d", len(cfg.Routing.Rules))
	}
}

func TestLoad_AllowsSameRouteDifferentMethods(t *testing.T) {
	yaml := `
targets:
  - name: a
    url: http://a:9000
  - name: b
    url: http://b:9000
routing:
  rules:
    - {host: h, path_prefix: /api, target_name: a, methods: [GET], auth: {required: true}}
    - {host: h, path_prefix: /api, target_name: b, methods: [POST]}
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err != nil {
		t.Fatalf("rules with different methods are different pools and must load: %v", err)
	}
}

func TestConfig_MaxRequestBodySizeDefault(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Server.EffectiveMaxRequestBodySize(); got != 10<<20 {
		t.Errorf("omitted max_request_body_size effective = %d, want %d", got, 10<<20)
	}
	if cfg.Server.MaxRequestBodySize == nil {
		t.Fatal("omitted max_request_body_size must materialize the 10 MiB default")
	}
}

func TestConfig_MaxRequestBodySizeZeroIsUnlimited(t *testing.T) {
	yaml := `
server:
  max_request_body_size: 0
targets:
  - name: "api"
    url: "http://api:9001"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Server.EffectiveMaxRequestBodySize(); got != 0 {
		t.Errorf("explicit max_request_body_size: 0 must mean unlimited, got effective %d", got)
	}
}

func TestConfig_MaxRequestBodySizeExplicitLimit(t *testing.T) {
	yaml := `
server:
  max_request_body_size: 1048576
targets:
  - name: "api"
    url: "http://api:9001"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Server.EffectiveMaxRequestBodySize(); got != 1048576 {
		t.Errorf("explicit max_request_body_size effective = %d, want 1048576", got)
	}
}

func hasWarning(warnings []string, want string) bool {
	for _, w := range warnings {
		if w == want {
			return true
		}
	}
	return false
}

func TestLoad_WarnsOnUnknownKeys(t *testing.T) {
	yaml := `
bogus_top: true
server:
  port: 8080
  bogus_nested: 1
headers:
  forward_headers: true
targets:
  - name: "api"
    url: "http://api:9001"
    bogus_target: x
`
	path := writeTempConfig(t, yaml)
	_, warnings, err := Load(path)
	if err != nil {
		t.Fatalf("unknown keys must not fail loading: %v", err)
	}
	for _, want := range []string{"bogus_top", "server.bogus_nested", "headers.forward_headers", "targets.bogus_target"} {
		if !hasWarning(warnings, want) {
			t.Errorf("expected warning %q, got %v", want, warnings)
		}
	}
}

func TestLoad_NoWarningsOnFullyTaggedConfig(t *testing.T) {
	yaml := `
application:
  env: "dev"
  health_check: true
  circuit_breaker: true
  metrics_enabled: false
  metrics_allowed_ips: ["10.0.0.1"]
  max_idle_conns_per_host: 100
server:
  port: 8080
  read_timeout: 5s
  write_timeout: 10s
  idle_timeout: 120s
  max_request_body_size: 1048576
tls:
  enabled: false
  port: 443
  http_port: 80
  domains: ["api.example.com"]
  email: "admin@example.com"
  cache_dir: "/var/lib/api-gateway/certs"
  staging: false
  redirect_http: true
  directory_url: ""
static:
  apps:
    - path_prefix: "/"
      root_dir: "/srv"
      index_file: "index.html"
      max_age: 60
  skip_prefixes: ["/api"]
targets:
  - name: "api"
    url: "http://api:9001"
    timeout: 5s
    path_prefix: "/api"
    strip_prefix: true
    weight: 1
    health_check: "/health"
jwt:
  secret_key: "secret"
  public_key_file: ""
  algorithm: "HS256"
  validate_exp: true
  validate_iss: false
  expected_iss: ""
  validate_aud: false
  expected_aud: ""
  claim_mappings: ["sub"]
  required: false
basic_auth:
  enabled: false
  username: "u"
  password: "p"
  skip_paths: ["/health"]
logging:
  level: "info"
  format: "json"
  access_log: false
headers:
  strip_authorization: true
  claim_to_header:
    sub: "X-User-ID"
  add_headers:
    X-Gateway: "v1"
  sign_header: "X-Sign"
  cors:
    enabled: true
    allowed_origins: ["*"]
    allowed_methods: ["GET"]
    allowed_headers: ["Authorization"]
    expose_headers: ["X-User-ID"]
    max_age: 60
routing:
  rules:
    - host: "api.example.com"
      path_prefix: "/api"
      target_name: "api"
      methods: ["GET"]
      strip_path: true
      auth:
        required: true
        roles: ["admin"]
        roles_all: ["mfa"]
        strip_token: false
      rate_limit:
        requests_per_second: 10
        burst: 20
  global_limit:
    requests_per_second: 100
    burst: 200
permissions:
  enabled: false
  service_url: "http://perm"
  cache_ttl: 60s
  header_name: "X-Perm"
  invalidate_token: "t"
  api_key: "k"
webhooks:
  - name: "wh"
    transport: "webhook"
    nats_url: ""
    subject: ""
    webhook_url: "http://hook"
    trigger: "on_response"
    methods: ["POST"]
    on_status_codes: [200]
    exclude_paths: ["/health"]
    async: false
    include_request_body: true
    include_response_body: false
    batch_size: 10
    flush_interval: 100ms
discovery:
  enabled: false
  provider: "docker"
  host: "unix:///var/run/docker.sock"
  api_version: "v1.41"
  label_prefix: "gateway"
  service_name_labels: ["a"]
  network: "net"
  debounce: 1s
  resync_interval: 1m
  default_timeout: 1s
  state_file: "/tmp/state.json"
`
	path := writeTempConfig(t, yaml)
	_, warnings, err := Load(path)
	if err != nil {
		t.Fatalf("fully tagged valid config must load: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no unknown-key warnings, got %v", warnings)
	}
}

func TestLoad_AuthRolesAll(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
routing:
  rules:
    - path_prefix: "/api"
      target_name: "api"
      auth:
        required: true
        roles: ["admin", "support"]
        roles_all: ["mfa", "verified"]
`
	path := writeTempConfig(t, yaml)
	cfg, warnings, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected no unknown-key warnings, got %v", warnings)
	}
	auth := cfg.Routing.Rules[0].Auth
	if auth == nil {
		t.Fatal("expected auth block")
	}
	if len(auth.Roles) != 2 || auth.Roles[0] != "admin" {
		t.Errorf("roles: got %v", auth.Roles)
	}
	if len(auth.RolesAll) != 2 || auth.RolesAll[0] != "mfa" {
		t.Errorf("roles_all: got %v", auth.RolesAll)
	}
}

func TestLoad_PermissionsEndpointDefaults(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
permissions:
  enabled: true
  service_url: "http://perm"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Permissions.Method != "GET" {
		t.Errorf("default permissions.method = %q, want GET", cfg.Permissions.Method)
	}
	if cfg.Permissions.Path != "/api/v1/users/{user_id}/effective-permissions" {
		t.Errorf("default permissions.path = %q", cfg.Permissions.Path)
	}
	if cfg.Permissions.APIKeyHeader != "X-API-Key" {
		t.Errorf("default permissions.api_key_header = %q, want X-API-Key", cfg.Permissions.APIKeyHeader)
	}
}

func TestLoad_PermissionsEndpointCustom(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
permissions:
  enabled: true
  service_url: "http://perm"
  method: "POST"
  path: "/v2/users/{user_id}/perms"
  api_key_header: "Authorization"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Permissions.Method != "POST" {
		t.Errorf("permissions.method = %q, want POST", cfg.Permissions.Method)
	}
	if cfg.Permissions.Path != "/v2/users/{user_id}/perms" {
		t.Errorf("permissions.path = %q", cfg.Permissions.Path)
	}
	if cfg.Permissions.APIKeyHeader != "Authorization" {
		t.Errorf("permissions.api_key_header = %q, want Authorization", cfg.Permissions.APIKeyHeader)
	}
}

func TestLoad_PermissionsEnabledRequiresServiceURL(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
permissions:
  enabled: true
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected error when permissions enabled without service_url")
	}
}

func TestLoad_PermissionsPathRequiresUserIDPlaceholder(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
permissions:
  enabled: true
  service_url: "http://perm"
  path: "/api/v1/users/effective-permissions"
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected error when permissions.path lacks {user_id}")
	}
}

func TestLoad_PermissionsRejectsInvalidMethod(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
permissions:
  enabled: true
  service_url: "http://perm"
  method: "GE T"
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err == nil {
		t.Fatal("expected error for permissions.method with whitespace")
	}
}

func TestValidate_PermissionsRejectsEmptyMethod(t *testing.T) {
	cfg := &Config{
		Targets: []TargetConfig{{Name: "api", URL: "http://api:9001"}},
		Permissions: PermissionsConfig{
			Enabled:    true,
			ServiceURL: "http://perm",
			Path:       "/api/v1/users/{user_id}/effective-permissions",
			Method:     "",
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty permissions.method")
	}
}

func TestLoad_EnvSubstitution(t *testing.T) {
	t.Setenv("TEST_ENV_VALUE", "prod-x")
	path := writeTempConfig(t, `
application:
  env: "${TEST_ENV_VALUE}"
targets:
  - name: backend
    url: "http://backend:80"
`)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Env != "prod-x" {
		t.Fatalf("env = %q, want %q", cfg.Env, "prod-x")
	}
}

func TestLoad_MissingEnvFails(t *testing.T) {
	os.Unsetenv("TEST_MISSING_ENV")
	path := writeTempConfig(t, `
application:
  env: "${TEST_MISSING_ENV}"
`)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for undefined env var")
	}
	if !strings.Contains(err.Error(), "TEST_MISSING_ENV") {
		t.Fatalf("error %q does not name the missing variable", err)
	}
}

func TestLoad_EmptyEnvFails(t *testing.T) {
	t.Setenv("TEST_EMPTY_ENV", "")
	path := writeTempConfig(t, `
application:
  env: "${TEST_EMPTY_ENV}"
`)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty env var")
	}
	if !strings.Contains(err.Error(), "TEST_EMPTY_ENV") {
		t.Fatalf("error %q does not name the empty variable", err)
	}
}

func TestLoad_MultipleMissingEnvsListed(t *testing.T) {
	os.Unsetenv("TEST_MISS_B")
	os.Unsetenv("TEST_MISS_A")
	path := writeTempConfig(t, `
application:
  env: "${TEST_MISS_B}"
jwt:
  secret_key: "${TEST_MISS_A}"
`)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for undefined env vars")
	}
	if !strings.Contains(err.Error(), "TEST_MISS_A") || !strings.Contains(err.Error(), "TEST_MISS_B") {
		t.Fatalf("error %q must name both variables", err)
	}
}

func TestLoad_EscapedEnvStaysLiteral(t *testing.T) {
	path := writeTempConfig(t, `
application:
  env: "$${LITERAL}"
targets:
  - name: backend
    url: "http://backend:80"
`)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Env != "${LITERAL}" {
		t.Fatalf("env = %q, want %q", cfg.Env, "${LITERAL}")
	}
}

func TestLoadLenient_MissingEnvStaysLiteral(t *testing.T) {
	os.Unsetenv("TEST_LENIENT_MISSING")
	path := writeTempConfig(t, `
application:
  env: "${TEST_LENIENT_MISSING}"
targets:
  - name: backend
    url: "http://backend:80"
`)
	cfg, _, err := LoadLenient(path)
	if err != nil {
		t.Fatalf("lenient load must not fail on a missing env var: %v", err)
	}
	if cfg.Env != "${TEST_LENIENT_MISSING}" {
		t.Fatalf("env = %q, want literal %q", cfg.Env, "${TEST_LENIENT_MISSING}")
	}
}

func TestLoadLenient_ExpandsDefinedEnv(t *testing.T) {
	t.Setenv("TEST_LENIENT_VALUE", "prod-x")
	path := writeTempConfig(t, `
application:
  env: "${TEST_LENIENT_VALUE}"
targets:
  - name: backend
    url: "http://backend:80"
`)
	cfg, _, err := LoadLenient(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Env != "prod-x" {
		t.Fatalf("env = %q, want %q", cfg.Env, "prod-x")
	}
}

func TestLoadLenient_NoTargets(t *testing.T) {
	path := writeTempConfig(t, "targets: []\n")
	cfg, _, err := LoadLenient(path)
	if err != nil {
		t.Fatalf("lenient load must not require targets: %v", err)
	}
	if len(cfg.Targets) != 0 {
		t.Fatalf("targets = %d, want 0", len(cfg.Targets))
	}
}

func TestLoadLenient_WarnsOnUnknownKeys(t *testing.T) {
	path := writeTempConfig(t, `
bogus_top: true
server:
  port: 8080
  bogus_nested: 1
targets:
  - name: "api"
    url: "http://api:9001"
    bogus_target: x
`)
	_, warnings, err := LoadLenient(path)
	if err != nil {
		t.Fatalf("unknown keys must not fail lenient loading: %v", err)
	}
	for _, want := range []string{"bogus_top", "server.bogus_nested", "targets.bogus_target"} {
		if !hasWarning(warnings, want) {
			t.Errorf("expected warning %q, got %v", want, warnings)
		}
	}
}

func TestLoad_IdentityProviders(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
jwt:
  secret_key: "our-secret"
identity:
  enabled: true
  selection: ["partner-x"]
  user_lookup:
    service_url: "http://passport:8085"
    hmac_secret: "internal-secret"
  providers:
    - name: "partner-x"
      enabled: true
      algorithm: "HS256"
      secret_key: "partner-secret"
      subject_provider: "cml"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Identity.Enabled {
		t.Fatal("expected identity enabled")
	}
	if cfg.Identity.UserLookup.CacheTTL != 300*time.Second {
		t.Fatalf("expected default cache ttl 300s, got %v", cfg.Identity.UserLookup.CacheTTL)
	}
	if cfg.Identity.Providers[0].SubjectProvider != "cml" {
		t.Fatalf("expected subject_provider cml, got %q", cfg.Identity.Providers[0].SubjectProvider)
	}
	if cfg.Identity.Providers[0].SubjectClaim != "sub" {
		t.Fatalf("expected default subject_claim sub, got %q", cfg.Identity.Providers[0].SubjectClaim)
	}
	if cfg.Identity.Providers[0].SecretKey != "partner-secret" {
		t.Fatalf("expected partner secret, got %q", cfg.Identity.Providers[0].SecretKey)
	}
}

func TestLoad_IdentityEnabledWithoutProviders(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
identity:
  enabled: true
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for identity enabled without providers")
	}
}

func TestLoad_IdentityDuplicateProviderName(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
identity:
  enabled: true
  user_lookup:
    service_url: "http://passport:8085"
  providers:
    - name: "dup"
      algorithm: "HS256"
      secret_key: "a"
      subject_provider: "cml"
    - name: "dup"
      algorithm: "HS256"
      secret_key: "b"
      subject_provider: "cml"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate provider name")
	}
}

func TestLoad_IdentityProviderSecretEqualsJWTSecret(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
jwt:
  secret_key: "our-secret"
identity:
  enabled: true
  user_lookup:
    service_url: "http://passport:8085"
    hmac_secret: "internal-secret"
  providers:
    - name: "partner"
      enabled: true
      algorithm: "HS256"
      secret_key: "our-secret"
      subject_provider: "cml"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error when provider secret equals jwt.secret_key")
	}
	if !strings.Contains(err.Error(), "partner") {
		t.Fatalf("error must name the provider, got: %v", err)
	}
}

func TestLoad_IdentityProviderSecretEqualsAPIKey(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
jwt:
  secret_key: "our-secret"
permissions:
  api_key: "php-secret"
identity:
  enabled: true
  user_lookup:
    service_url: "http://passport:8085"
    hmac_secret: "internal-secret"
  providers:
    - name: "partner"
      enabled: true
      algorithm: "HS256"
      secret_key: "php-secret"
      subject_provider: "cml"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error when provider secret equals permissions.api_key")
	}
	if !strings.Contains(err.Error(), "partner") {
		t.Fatalf("error must name the provider, got: %v", err)
	}
}

func TestLoad_IdentityDistinctSecretsAllowed(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
jwt:
  secret_key: "our-secret"
permissions:
  api_key: "php-secret"
identity:
  enabled: true
  user_lookup:
    service_url: "http://passport:8085"
    hmac_secret: "internal-secret"
  providers:
    - name: "partner"
      enabled: true
      algorithm: "HS256"
      secret_key: "partner-secret"
      subject_provider: "cml"
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err != nil {
		t.Fatalf("distinct secrets must be accepted, got: %v", err)
	}
}

func TestLoad_IdentityProviderWithoutSubjectProviderRejected(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
identity:
  enabled: true
  user_lookup:
    service_url: "http://passport:8085"
    hmac_secret: "internal-secret"
  providers:
    - name: "partner"
      enabled: true
      algorithm: "HS256"
      secret_key: "partner-secret"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for enabled provider without subject_provider")
	}
	if !strings.Contains(err.Error(), "partner") || !strings.Contains(err.Error(), "subject_provider") {
		t.Fatalf("error must name the provider and subject_provider, got: %v", err)
	}
}

// Disabled-провайдер остаётся заготовкой: subject_provider от него не требуется.
func TestLoad_IdentityDisabledProviderWithoutSubjectProviderAllowed(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
identity:
  enabled: true
  user_lookup:
    service_url: "http://passport:8085"
    hmac_secret: "internal-secret"
  providers:
    - name: "partner"
      enabled: true
      algorithm: "HS256"
      secret_key: "partner-secret"
      subject_provider: "cml"
    - name: "draft"
      enabled: false
      algorithm: "HS256"
      secret_key: "draft-secret"
`
	path := writeTempConfig(t, yaml)
	if _, _, err := Load(path); err != nil {
		t.Fatalf("disabled provider must not require subject_provider, got: %v", err)
	}
}

func TestLoad_IdentityJwksURLAccepted(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
identity:
  enabled: true
  user_lookup:
    service_url: "http://passport:8085"
    hmac_secret: "internal-secret"
  providers:
    - name: "cml"
      enabled: true
      algorithm: "RS256"
      jwks_url: "https://cml/.well-known/jwks"
      subject_provider: "cml"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("RS256 + jwks_url must be accepted, got: %v", err)
	}
	if cfg.Identity.Providers[0].JwksURL != "https://cml/.well-known/jwks" {
		t.Fatalf("unexpected jwks_url: %q", cfg.Identity.Providers[0].JwksURL)
	}
}

func TestLoad_IdentityJwksURLWithHSRejected(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
identity:
  enabled: true
  user_lookup:
    service_url: "http://passport:8085"
    hmac_secret: "internal-secret"
  providers:
    - name: "cml"
      enabled: true
      algorithm: "HS256"
      secret_key: "partner-secret"
      subject_provider: "cml"
      jwks_url: "https://cml/.well-known/jwks"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for HS256 with jwks_url")
	}
	if !strings.Contains(err.Error(), "cml") || !strings.Contains(err.Error(), "jwks_url") {
		t.Fatalf("error must name the provider and jwks_url, got: %v", err)
	}
}

func TestLoad_IdentityHSProviderWithoutSecretKeyRejected(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
identity:
  enabled: true
  user_lookup:
    service_url: "http://passport:8085"
    hmac_secret: "internal-secret"
  providers:
    - name: "partner"
      enabled: true
      algorithm: "HS256"
      subject_provider: "cml"
`
	path := writeTempConfig(t, yaml)
	_, _, err := Load(path)
	if err == nil {
		t.Fatal("expected error for HS* provider without secret_key")
	}
	if !strings.Contains(err.Error(), "secret_key") {
		t.Fatalf("error must mention secret_key, got: %v", err)
	}
}

func TestRoutingRule_ProtocolLimits(t *testing.T) {
	raw := []byte(`
targets:
  - name: dav
    url: "http://storage:8091"
routing:
  rules:
    - host: "dav.example"
      path_prefix: "/dav/"
      target_name: "dav"
      max_request_body_size: 536870912
      read_timeout: 15m
      write_timeout: 1h
      preserve_host: true
      buffer_request_body: false
`)
	cfg := &Config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	rule := cfg.Routing.Rules[0]
	if rule.MaxRequestBodySize == nil || *rule.MaxRequestBodySize != 536870912 {
		t.Errorf("max_request_body_size = %v", rule.MaxRequestBodySize)
	}
	if rule.ReadTimeout != 15*time.Minute || rule.WriteTimeout != time.Hour {
		t.Errorf("timeouts = %s / %s", rule.ReadTimeout, rule.WriteTimeout)
	}
	if !rule.PreserveHost {
		t.Error("preserve_host not parsed")
	}
	if rule.BufferRequestBodyEnabled() {
		t.Error("buffer_request_body: false ignored")
	}
	if got := rule.EffectiveMaxRequestBodySize(10 << 20); got != 536870912 {
		t.Errorf("effective limit = %d, route must override server", got)
	}

	// Без настроек маршрут наследует серверный лимит и буферизует тело.
	plain := RoutingRule{}
	if plain.BufferRequestBodyEnabled() != true {
		t.Error("default buffer_request_body must stay true")
	}
	if got := plain.EffectiveMaxRequestBodySize(42); got != 42 {
		t.Errorf("default limit = %d, want server 42", got)
	}
}

// Воркеры приходят на отдельный порт, поэтому Host содержит :8444. Правила
// маршрутизации заданы без порта — порт не должен ломать выбор таргета.
func TestFindTargetForPath_HostWithPort(t *testing.T) {
	yaml := `
targets:
  - name: "tasktracker"
    url: "http://tasktracker:8080"
routing:
  rules:
    - host: "tracker.sarnas.ru"
      path_prefix: "/"
      target_name: "tasktracker"
`
	cfg, _, err := Load(writeTempConfig(t, yaml))
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"tracker.sarnas.ru", "tracker.sarnas.ru:8444", "TRACKER.SARNAS.RU:443"} {
		target, rule := cfg.FindTargetForPath("/api/v1/workers/register", "POST", host)
		if target == nil || rule == nil || rule.TargetName != "tasktracker" {
			t.Errorf("host %q did not match the tracker rule", host)
		}
	}
}

func TestLoad_AuthConnector(t *testing.T) {
	yaml := `
targets:
  - name: "api"
    url: "http://api:9001"
routing:
  rules:
    - path_prefix: "/api/keys"
      target_name: "api"
      auth:
        connector: "apikey"
        roles: ["admin"]
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routing.Rules) != 1 {
		t.Fatalf("rules = %d", len(cfg.Routing.Rules))
	}
	auth := cfg.Routing.Rules[0].Auth
	if auth == nil || auth.Connector != "apikey" || len(auth.Roles) != 1 || auth.Roles[0] != "admin" {
		t.Fatalf("auth = %+v", auth)
	}
}

func TestLoad_DiscoveryModule(t *testing.T) {
	yaml := `
discovery:
  enabled: true
  module: "file"
  default_timeout: 3s
plugins:
  file:
    path: "/etc/gateway/services.json"
`
	path := writeTempConfig(t, yaml)
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Discovery == nil || cfg.Discovery.Module != "file" || cfg.Discovery.DefaultTimeout != 3*time.Second {
		t.Fatalf("discovery = %+v", cfg.Discovery)
	}
	if cfg.Plugins["file"]["path"] != "/etc/gateway/services.json" {
		t.Fatalf("plugins = %v", cfg.Plugins)
	}
}

func TestValidate_TargetRest(t *testing.T) {
	base := `
targets:
  - name: api
    url: http://api:9001
    rest:
%s
`
	for _, tc := range []struct {
		name    string
		rest    string
		wantErr bool
	}{
		{"enabled defaults", "      enabled: true\n", false},
		{"valid bounds", "      enabled: true\n      base: 30s\n      max: 5m\n", false},
		{"negative base", "      enabled: true\n      base: -1s\n", true},
		{"max below base", "      enabled: true\n      base: 10m\n      max: 1m\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempConfig(t, fmt.Sprintf(base, tc.rest))
			cfg, _, err := Load(path)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error for invalid rest config")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			rest := cfg.Targets[0].Rest
			if rest == nil || !rest.Enabled {
				t.Fatalf("rest = %+v", rest)
			}
		})
	}
}

func TestRestConfigDefaults(t *testing.T) {
	r := &RestConfig{Enabled: true}
	if r.EffectiveBase() != time.Minute {
		t.Fatalf("base = %v, want 1m", r.EffectiveBase())
	}
	if r.EffectiveMax() != 30*time.Minute {
		t.Fatalf("max = %v, want 30m", r.EffectiveMax())
	}
	var nilRest *RestConfig
	if nilRest.EffectiveBase() != time.Minute || nilRest.EffectiveMax() != 30*time.Minute {
		t.Fatal("nil rest must yield defaults")
	}
}
