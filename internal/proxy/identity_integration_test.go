package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"code.sarnas.ru/api-gateway/internal/config"
)

func TestModifyRequest_ExternalTokenMapsToOurUser(t *testing.T) {
	lookupSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/internal/user-by-subject" {
			t.Errorf("unexpected lookup path %s", r.URL.Path)
		}
		if r.URL.Query().Get("provider") != "cml" || r.URL.Query().Get("subject") != "uuid-1" {
			t.Errorf("unexpected lookup query %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":42,"email":"partner@example.com","full_name":"P","is_active":true,"roles":["viewer"]}}`))
	}))
	defer lookupSrv.Close()

	cfg := &config.Config{}
	cfg.Server.Port = 8080
	cfg.JWT.SecretKey = "our-secret"
	cfg.JWT.Algorithm = "HS256"
	cfg.Permissions.APIKey = "php-secret"
	cfg.Headers.SignHeader = "X-User-Signature"
	cfg.Targets = []config.TargetConfig{{Name: "api", URL: "http://127.0.0.1:1", Timeout: time.Second}}
	cfg.Identity = config.IdentityConfig{
		Enabled: true,
		UserLookup: config.IdentityUserLookupConfig{
			ServiceURL: lookupSrv.URL, HMACSecret: "internal-secret", CacheTTL: time.Minute,
		},
		Providers: []config.IdentityProviderConfig{{
			Name: "partner", Enabled: true, Algorithm: "HS256",
			SecretKey: "partner-secret", ValidateExp: true, SubjectProvider: "cml",
		}},
	}

	mp, err := NewMultiProxy(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "uuid-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, _ := tok.SignedString([]byte("partner-secret"))

	req := httptest.NewRequest("GET", "/api/v1/anything", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rule := &config.RoutingRule{Auth: &config.AuthRule{Required: boolPtr(true)}}

	if err := mp.modifyRequest(req, &cfg.Targets[0], rule); err != nil {
		t.Fatalf("modifyRequest error: %v", err)
	}
	if got := req.Header.Get("X-User-ID"); got != "42" {
		t.Fatalf("expected X-User-ID 42, got %q", got)
	}
	if got := req.Header.Get("X-User-Email"); got != "partner@example.com" {
		t.Fatalf("unexpected X-User-Email %q", got)
	}

	mac := hmac.New(sha256.New, []byte("php-secret"))
	mac.Write([]byte("42"))
	want := hex.EncodeToString(mac.Sum(nil))
	if got := req.Header.Get("X-User-Signature"); got != want {
		t.Fatalf("signature mismatch: got %q want %q", got, want)
	}
	// Opting in a monitoring route changes only its signature, and signs the
	// resolved numeric passport ID rather than the untrusted external UUID.
	req = httptest.NewRequest("POST", "/api/reports/own", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rule.SignV2 = true
	if err := mp.modifyRequest(req, &cfg.Targets[0], rule); err != nil {
		t.Fatal(err)
	}
	stamp := req.Header.Get("X-User-Timestamp")
	if stamp == "" || req.Header.Get("X-User-ID") != "42" {
		t.Fatal("v2 lost numeric identity")
	}
	mac = hmac.New(sha256.New, []byte("php-secret"))
	mac.Write([]byte("42\nPOST\n/api/reports/own\n" + stamp))
	if req.Header.Get("X-User-Signature") != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("wrong v2 signature")
	}
}

// TestModifyRequest_ExternalTokenRoleGate verifies that the external identity
// path mirrors the our-JWT role semantics: Auth.Roles is any-of and
// Auth.RolesAll is all-of.
func TestModifyRequest_ExternalTokenRoleGate(t *testing.T) {
	lookupSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/internal/user-by-subject" {
			t.Errorf("unexpected lookup path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":42,"email":"partner@example.com","is_active":true,"roles":["viewer","editor"]}}`))
	}))
	defer lookupSrv.Close()

	cfg := &config.Config{}
	cfg.Server.Port = 8080
	cfg.JWT.SecretKey = "our-secret"
	cfg.JWT.Algorithm = "HS256"
	cfg.Permissions.APIKey = "php-secret"
	cfg.Headers.SignHeader = "X-User-Signature"
	cfg.Targets = []config.TargetConfig{{Name: "api", URL: "http://127.0.0.1:1", Timeout: time.Second}}
	cfg.Identity = config.IdentityConfig{
		Enabled: true,
		UserLookup: config.IdentityUserLookupConfig{
			ServiceURL: lookupSrv.URL, HMACSecret: "internal-secret", CacheTTL: time.Minute,
		},
		Providers: []config.IdentityProviderConfig{{
			Name: "partner", Enabled: true, Algorithm: "HS256",
			SecretKey: "partner-secret", ValidateExp: true, SubjectProvider: "cml",
		}},
	}

	mp, err := NewMultiProxy(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "uuid-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, _ := tok.SignedString([]byte("partner-secret"))

	cases := []struct {
		name    string
		auth    *config.AuthRule
		wantErr bool
	}{
		{"any-of one of several allowed", &config.AuthRule{Required: boolPtr(true), Roles: []string{"editor", "admin"}}, false},
		{"any-of none rejected", &config.AuthRule{Required: boolPtr(true), Roles: []string{"admin"}}, true},
		{"all-of missing role rejected", &config.AuthRule{Required: boolPtr(true), RolesAll: []string{"viewer", "admin"}}, true},
		{"all-of all present allowed", &config.AuthRule{Required: boolPtr(true), RolesAll: []string{"viewer", "editor"}}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/anything", nil)
			req.Header.Set("Authorization", "Bearer "+signed)
			err := mp.modifyRequest(req, &cfg.Targets[0], &config.RoutingRule{Auth: tc.auth})
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestModifyRequest_ExternalTokenAppliesSignV3 verifies that a resolved
// external identity also gets the per-route HMAC v3 signature — without it
// admin-backend routes (sign_v3) reject external tokens with 401.
func TestModifyRequest_ExternalTokenAppliesSignV3(t *testing.T) {
	lookupSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/internal/user-by-subject" {
			t.Errorf("unexpected lookup path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":42,"email":"partner@example.com","is_active":true,"roles":["admin"]}}`))
	}))
	defer lookupSrv.Close()

	cfg := &config.Config{}
	cfg.Server.Port = 8080
	cfg.JWT.SecretKey = "our-secret"
	cfg.JWT.Algorithm = "HS256"
	cfg.Targets = []config.TargetConfig{{Name: "api", URL: "http://127.0.0.1:1", Timeout: time.Second}}
	cfg.Identity = config.IdentityConfig{
		Enabled: true,
		UserLookup: config.IdentityUserLookupConfig{
			ServiceURL: lookupSrv.URL, HMACSecret: "internal-secret", CacheTTL: time.Minute,
		},
		Providers: []config.IdentityProviderConfig{{
			Name: "partner", Enabled: true, Algorithm: "HS256",
			SecretKey: "partner-secret", ValidateExp: true, SubjectProvider: "cml",
		}},
	}

	mp, err := NewMultiProxy(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "uuid-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, _ := tok.SignedString([]byte("partner-secret"))

	req := httptest.NewRequest("GET", "/api/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rule := &config.RoutingRule{
		PathPrefix: "/api/v1",
		Auth:       &config.AuthRule{Required: boolPtr(true)},
		SignV3:     &config.SignV3Config{ServiceID: "admin-front", KeyID: "1", Secret: "v3-secret"},
	}

	if err := mp.modifyRequest(req, &cfg.Targets[0], rule); err != nil {
		t.Fatalf("modifyRequest error: %v", err)
	}

	if got := req.Header.Get("X-Service-ID"); got != "admin-front" {
		t.Fatalf("X-Service-ID: got %q want admin-front", got)
	}
	if got := req.Header.Get("X-Key-ID"); got != "1" {
		t.Fatalf("X-Key-ID: got %q want 1", got)
	}
	if got := req.Header.Get("X-User-ID"); got != "42" {
		t.Fatalf("X-User-ID: got %q want 42", got)
	}

	tsStr := req.Header.Get("X-User-Timestamp")
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		t.Fatalf("X-User-Timestamp %q not an int: %v", tsStr, err)
	}
	wantSig, _ := signV3("admin-front", "42", "GET", "/api/v1/jobs", "v3-secret", ts)
	if got := req.Header.Get("X-User-Signature"); got != wantSig {
		t.Fatalf("X-User-Signature: got %q want %q", got, wantSig)
	}
}
