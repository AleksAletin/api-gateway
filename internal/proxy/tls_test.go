package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"code.sarnas.ru/api-gateway/internal/config"
)

// writeTestCA создаёт self-signed CA в PEM во временном каталоге теста и
// возвращает путь к файлу и пул с этим CA.
func writeTestCA(t *testing.T) (string, *x509.CertPool) {
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
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	pool, err := config.LoadClientCAPool(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, pool
}

func TestBuildCertManager_Staging(t *testing.T) {
	m := buildCertManager(&config.TLSConfig{
		Domains:  []string{"api.example.com"},
		Email:    "admin@example.com",
		CacheDir: "/var/lib/api-gateway/certs",
		Staging:  true,
	})

	if m.Client == nil || m.Client.DirectoryURL != letsEncryptStagingDirectory {
		t.Fatalf("staging DirectoryURL = %v, want %q", m.Client, letsEncryptStagingDirectory)
	}
	cache, ok := m.Cache.(autocert.DirCache)
	if !ok {
		t.Fatalf("cache type = %T, want autocert.DirCache", m.Cache)
	}
	if want := filepath.Join("/var/lib/api-gateway/certs", "staging"); string(cache) != want {
		t.Errorf("staging cache dir = %q, want %q", string(cache), want)
	}
}

func TestBuildCertManager_Production(t *testing.T) {
	m := buildCertManager(&config.TLSConfig{
		Domains:  []string{"api.example.com"},
		Email:    "admin@example.com",
		CacheDir: "/var/lib/api-gateway/certs",
	})

	if m.Client != nil && m.Client.DirectoryURL != "" {
		t.Errorf("production must use autocert's default directory, got %q", m.Client.DirectoryURL)
	}
	cache, ok := m.Cache.(autocert.DirCache)
	if !ok {
		t.Fatalf("cache type = %T, want autocert.DirCache", m.Cache)
	}
	if string(cache) != "/var/lib/api-gateway/certs" {
		t.Errorf("production cache dir = %q, want %q", string(cache), "/var/lib/api-gateway/certs")
	}
}

func TestBuildCertManager_DirectoryURLOverride(t *testing.T) {
	m := buildCertManager(&config.TLSConfig{
		Domains:      []string{"api.example.com"},
		Email:        "admin@example.com",
		CacheDir:     "/var/lib/api-gateway/certs",
		Staging:      true,
		DirectoryURL: "https://acme.internal/directory",
	})

	if m.Client == nil || m.Client.DirectoryURL != "https://acme.internal/directory" {
		t.Fatalf("DirectoryURL override = %v, want %q", m.Client, "https://acme.internal/directory")
	}
	cache, ok := m.Cache.(autocert.DirCache)
	if !ok {
		t.Fatalf("cache type = %T, want autocert.DirCache", m.Cache)
	}
	if want := filepath.Join("/var/lib/api-gateway/certs", "staging"); string(cache) != want {
		t.Errorf("staging cache dir = %q, want %q", string(cache), want)
	}
}

func TestMetricsOverHTTPHandler(t *testing.T) {
	main := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("metrics"))
	})
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMovedPermanently)
	})
	h := metricsOverHTTPHandler(main, redirect)

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/metrics", http.StatusOK},
		{"/metrics/prometheus", http.StatusOK},
		{"/metrics/other", http.StatusMovedPermanently},
		{"/", http.StatusMovedPermanently},
		{"/api/blog", http.StatusMovedPermanently},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.path, rec.Code, tc.want)
		}
	}
}

func TestBuildWorkerTLSConfig_RequiresAndVerifiesClientCert(t *testing.T) {
	_, pool := writeTestCA(t)

	cfg := buildWorkerTLSConfig((&autocert.Manager{Prompt: autocert.AcceptTOS}).TLSConfig(), pool)

	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs must be set")
	}
	if !cfg.ClientCAs.Equal(pool) {
		t.Error("ClientCAs must be the pool loaded from worker_client_ca_file")
	}
	if cfg.GetCertificate == nil {
		t.Error("GetCertificate must come from the autocert manager (same server certificate as :443)")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
}

func TestWorkerOnlyHandler_AllowsOnlyWorkerPaths(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("worker"))
	})
	h := workerOnlyHandler(next)

	for _, tc := range []struct {
		name string
		path string
		want int
	}{
		{"worker register", "/api/v1/workers/register", http.StatusOK},
		{"worker subpath", "/api/v1/workers/71c1/leases/claim", http.StatusOK},
		{"nested worker path", "/api/v1/workers/71c1/leases/abc/release", http.StatusOK},
		{"admin approve", "/api/v1/workers/71c1/approve", http.StatusNotFound},
		{"admin drain", "/api/v1/workers/71c1/drain", http.StatusNotFound},
		{"worker collection", "/api/v1/workers/", http.StatusNotFound},
		{"base path", "/", http.StatusNotFound},
		{"auth api", "/api/v1/auth/login", http.StatusNotFound},
		{"other api", "/api/v1/client/me", http.StatusNotFound},
		{"metrics", "/metrics", http.StatusNotFound},
		{"health", "/health", http.StatusNotFound},
		{"lease secrets", "/api/v1/worker-leases/abc/secrets", http.StatusOK},
		{"lease collection", "/api/v1/worker-leases", http.StatusOK},
		{"traversal out of workers", "/api/v1/workers/../auth/login", http.StatusNotFound},
		{"worker heartbeat", "/api/v1/workers/71c1/heartbeat", http.StatusOK},
		{"prefix lookalike", "/api/v1/workers-other/heartbeat", http.StatusNotFound},
		{"lease lookalike", "/api/v1/worker-leases-other/x/secrets", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.want {
				t.Errorf("%s: got %d, want %d", tc.path, rec.Code, tc.want)
			}
		})
	}
}

// TT-139: при включённом mTLS-листенере публичный :443 не должен обслуживать
// протокол воркеров, иначе клиентский сертификат можно обойти.
func TestPublicWorkerMutedHandler_BlocksWorkerPaths(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := publicWorkerMutedHandler(next)
	for _, path := range []string{
		"/api/v1/workers/register",
		"/api/v1/workers/abc/leases/claim",
		"/api/v1/worker-leases/abc/secrets",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s on the public listener = %d, want 404", path, rec.Code)
		}
	}
	for _, path := range []string{"/healthz", "/api/v1/tasks"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want it to pass through", path, rec.Code)
		}
	}
}
