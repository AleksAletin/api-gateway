package identity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"code.sarnas.ru/api-gateway/internal/config"
)

func signHS256(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func lookupServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("email") {
		case "active@example.com":
			_, _ = w.Write([]byte(`{"data":{"id":42,"email":"active@example.com","full_name":"A","is_active":true,"roles":["viewer"]}}`))
		case "inactive@example.com":
			_, _ = w.Write([]byte(`{"data":{"id":43,"email":"inactive@example.com","is_active":false}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func managerCfg(serviceURL string) config.IdentityConfig {
	return config.IdentityConfig{
		Enabled:   true,
		Selection: []string{"partner"},
		UserLookup: config.IdentityUserLookupConfig{
			ServiceURL: serviceURL, HMACSecret: "internal-secret", CacheTTL: time.Minute,
		},
		Providers: []config.IdentityProviderConfig{{
			Name: "partner", Enabled: true, Algorithm: "HS256",
			SecretKey: "partner-secret", ValidateExp: true, EmailClaim: "email",
		}},
	}
}

func TestResolve_ValidPartnerToken(t *testing.T) {
	srv := lookupServer(t)
	defer srv.Close()

	m, err := NewManager(managerCfg(srv.URL), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	token := signHS256(t, "partner-secret", jwt.MapClaims{
		"email": "active@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	u, err := m.Resolve(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.ID != 42 || u.Email != "active@example.com" {
		t.Fatalf("unexpected user: %+v", u)
	}
}

func TestResolve_WrongSecret(t *testing.T) {
	srv := lookupServer(t)
	defer srv.Close()
	m, _ := NewManager(managerCfg(srv.URL), zap.NewNop())

	token := signHS256(t, "our-secret", jwt.MapClaims{
		"email": "active@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.Resolve(context.Background(), token); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestResolve_InactiveUser(t *testing.T) {
	srv := lookupServer(t)
	defer srv.Close()
	m, _ := NewManager(managerCfg(srv.URL), zap.NewNop())

	token := signHS256(t, "partner-secret", jwt.MapClaims{
		"email": "inactive@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.Resolve(context.Background(), token); err == nil {
		t.Fatal("expected error for inactive user")
	}
}

func TestResolve_NoEmailClaim(t *testing.T) {
	srv := lookupServer(t)
	defer srv.Close()
	m, _ := NewManager(managerCfg(srv.URL), zap.NewNop())

	token := signHS256(t, "partner-secret", jwt.MapClaims{
		"sub": "123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.Resolve(context.Background(), token); err == nil {
		t.Fatal("expected error when email claim missing")
	}
}

func TestResolve_SelectionExcludesProvider(t *testing.T) {
	srv := lookupServer(t)
	defer srv.Close()
	cfg := managerCfg(srv.URL)
	cfg.Selection = []string{"other"}

	m, err := NewManager(cfg, zap.NewNop())
	if m != nil {
		t.Fatal("expected nil manager when selection matches no enabled provider")
	}
	if err == nil {
		t.Fatal("expected error when selection matches no enabled provider")
	}
}

func TestResolve_EmptySelectionIncludesAllEnabled(t *testing.T) {
	srv := lookupServer(t)
	defer srv.Close()
	cfg := managerCfg(srv.URL)
	cfg.Selection = nil
	cfg.Providers = append(cfg.Providers, config.IdentityProviderConfig{
		Name: "other", Enabled: true, Algorithm: "HS256",
		SecretKey: "other-secret", ValidateExp: true, EmailClaim: "email",
	})

	m, err := NewManager(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	// Токен второго (тоже enabled) провайдера должен резолвиться при пустом селекторе.
	token := signHS256(t, "other-secret", jwt.MapClaims{
		"email": "active@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	u, err := m.Resolve(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.ID != 42 {
		t.Fatalf("unexpected user: %+v", u)
	}
}

func TestResolve_SelectedProviderRejectsToken(t *testing.T) {
	srv := lookupServer(t)
	defer srv.Close()
	cfg := managerCfg(srv.URL)
	cfg.Selection = []string{"partner"}
	cfg.Providers = append(cfg.Providers, config.IdentityProviderConfig{
		Name: "other", Enabled: true, Algorithm: "HS256",
		SecretKey: "other-secret", ValidateExp: true, EmailClaim: "email",
	})

	m, err := NewManager(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	// Токен невыбранного провайдера не должен приниматься выбранным.
	token := signHS256(t, "other-secret", jwt.MapClaims{
		"email": "active@example.com",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.Resolve(context.Background(), token); err == nil {
		t.Fatal("expected error when token is signed by a non-selected provider")
	}
}

func TestNewManager_UnknownSelectionWarns(t *testing.T) {
	srv := lookupServer(t)
	defer srv.Close()
	cfg := managerCfg(srv.URL)
	cfg.Selection = []string{"partner", "ghost"}

	core, logs := observer.New(zap.WarnLevel)
	m, err := NewManager(cfg, zap.New(core))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected manager when at least one selection entry is valid")
	}
	if got := logs.FilterMessage("identity: selection entry does not match an enabled provider").Len(); got != 1 {
		t.Fatalf("expected one warning for unknown selection entry, got %d: %v", got, logs.All())
	}
}

func TestResolve_BySubjectFirst(t *testing.T) {
	var subjectCalls, emailCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/internal/user-by-subject" {
			atomic.AddInt32(&subjectCalls, 1)
			if r.URL.Query().Get("provider") == "cml" && r.URL.Query().Get("subject") == "uuid-1" {
				_, _ = w.Write([]byte(`{"data":{"id":42,"email":"active@example.com","full_name":"A","is_active":true,"roles":["viewer"]}}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(&emailCalls, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := managerCfg(srv.URL)
	cfg.Providers[0].SubjectProvider = "cml"
	m, err := NewManager(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	token := signHS256(t, "partner-secret", jwt.MapClaims{
		"sub": "uuid-1", "email": "stale@example.com", "exp": time.Now().Add(time.Hour).Unix(),
	})
	u, err := m.Resolve(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.ID != 42 {
		t.Fatalf("unexpected user: %+v", u)
	}
	if atomic.LoadInt32(&emailCalls) != 0 {
		t.Fatal("email fallback must not be called when subject lookup succeeds")
	}
	if atomic.LoadInt32(&subjectCalls) != 1 {
		t.Fatalf("expected exactly one subject call, got %d", subjectCalls)
	}
}

func TestResolve_SubjectFailureNeverFallsBackToEmail(t *testing.T) {
	for _, scenario := range []string{"missing", "not_found", "inactive", "outage"} {
		t.Run(scenario, func(t *testing.T) {
			var emailCalls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/internal/user-by-subject" {
					switch scenario {
					case "inactive":
						_, _ = w.Write([]byte(`{"data":{"id":42,"is_active":false}}`))
					case "outage":
						w.WriteHeader(503)
					default:
						w.WriteHeader(404)
					}
					return
				}
				emailCalls.Add(1)
				_, _ = w.Write([]byte(`{"data":{"id":99,"email":"active@example.com","is_active":true}}`))
			}))
			defer srv.Close()
			cfg := managerCfg(srv.URL)
			cfg.Providers[0].SubjectProvider = "cml"
			// An additional provider trusting the same key must not bypass the denial.
			extra := cfg.Providers[0]
			extra.Name = "email-only"
			extra.SubjectProvider = ""
			cfg.Providers = append(cfg.Providers, extra)
			cfg.Selection = nil
			m, err := NewManager(cfg, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			claims := jwt.MapClaims{"email": "active@example.com", "exp": time.Now().Add(time.Hour).Unix()}
			if scenario != "missing" {
				claims["sub"] = "missing-or-blocked"
			}
			user, err := m.Resolve(context.Background(), signHS256(t, "partner-secret", claims))
			if err == nil || user != nil {
				t.Fatalf("unexpected identity: %+v %v", user, err)
			}
			if emailCalls.Load() != 0 {
				t.Fatal("email fallback was called")
			}
		})
	}
}

func TestResolve_SubjectLookupDisabledWithoutSubjectProvider(t *testing.T) {
	var subjectCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/internal/user-by-subject" {
			atomic.AddInt32(&subjectCalls, 1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"id":42,"email":"active@example.com","full_name":"A","is_active":true,"roles":["viewer"]}}`))
	}))
	defer srv.Close()

	m, err := NewManager(managerCfg(srv.URL), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	token := signHS256(t, "partner-secret", jwt.MapClaims{
		"sub": "uuid-1", "email": "active@example.com", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.Resolve(context.Background(), token); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&subjectCalls) != 0 {
		t.Fatal("subject endpoint must not be called without subject_provider")
	}
}
