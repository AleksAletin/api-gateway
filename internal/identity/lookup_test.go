package identity

import (
	"context"
	"crypto/hmac"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"code.sarnas.ru/api-gateway/internal/config"
)

// verifyHMACV2 повторяет серверную проверку go-hmac-auth VerifyRequest.
func verifyHMACV2(userID, method, path, ts, sig, secret string, now time.Time) bool {
	unix, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	issued := time.Unix(unix, 0)
	if d := now.Sub(issued); d > 5*time.Minute || d < -5*time.Minute {
		return false
	}
	expected, _ := signHMACV2(userID, method, path, secret, issued)
	return hmac.Equal([]byte(expected), []byte(sig))
}

func TestLookupClient_FetchFound(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Path != "/api/v1/internal/user-by-subject" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("provider") != "cml" || r.URL.Query().Get("subject") != "uuid-1" {
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
		uid := r.Header.Get(hmacUserIDHeader)
		sig := r.Header.Get(hmacSignatureHeader)
		ts := r.Header.Get(hmacTimestampHeader)
		if !verifyHMACV2(uid, r.Method, r.URL.Path, ts, sig, "internal-secret", time.Now()) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":7,"email":"partner@example.com","full_name":"Partner","is_active":true,"roles":["viewer"]}}`))
	}))
	defer srv.Close()

	c := newLookupClient(srv.URL, "internal-secret")
	u, err := c.fetchBySubject(context.Background(), "cml", "uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil || u.ID != 7 || u.Email != "partner@example.com" || !u.IsActive {
		t.Fatalf("unexpected user: %+v", u)
	}
	if len(u.Roles) != 1 || u.Roles[0] != "viewer" {
		t.Fatalf("unexpected roles: %+v", u.Roles)
	}
}

func TestLookupClient_TrailingSlashBaseURL(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		if r.URL.Path != "/api/v1/internal/user-by-subject" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		uid := r.Header.Get(hmacUserIDHeader)
		sig := r.Header.Get(hmacSignatureHeader)
		ts := r.Header.Get(hmacTimestampHeader)
		if !verifyHMACV2(uid, r.Method, r.URL.Path, ts, sig, "internal-secret", time.Now()) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"id":9,"email":"partner@example.com","is_active":true}}`))
	}))
	defer srv.Close()

	c := newLookupClient(srv.URL+"/", "internal-secret")
	u, err := c.fetchBySubject(context.Background(), "cml", "uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil || u.ID != 9 {
		t.Fatalf("unexpected user: %+v", u)
	}
	if !hit {
		t.Fatal("lookup server was not hit")
	}
}

func TestLookupClient_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newLookupClient(srv.URL, "internal-secret")
	u, err := c.fetchBySubject(context.Background(), "cml", "unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u != nil {
		t.Fatalf("expected nil user, got %+v", u)
	}
}

func TestResolver_CacheHitAndNegative(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.URL.Query().Get("subject") == "uuid-found" {
			_, _ = w.Write([]byte(`{"data":{"id":1,"email":"found@example.com","is_active":true}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := newResolver(config0(srv.URL))

	u, found, err := r.bySubject(context.Background(), "cml", "uuid-found")
	if err != nil || !found || u.ID != 1 {
		t.Fatalf("first lookup failed: u=%+v found=%v err=%v", u, found, err)
	}
	_, _, _ = r.bySubject(context.Background(), "cml", "uuid-found")
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected cache hit (1 call), got %d", atomic.LoadInt32(&calls))
	}

	_, found, err = r.bySubject(context.Background(), "cml", "uuid-missing")
	if err != nil || found {
		t.Fatalf("expected negative result, got found=%v err=%v", found, err)
	}
	_, _, _ = r.bySubject(context.Background(), "cml", "uuid-missing")
	if atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("expected negative cache (2 calls), got %d", atomic.LoadInt32(&calls))
	}
}

func config0(serviceURL string) config.IdentityUserLookupConfig {
	return config.IdentityUserLookupConfig{
		ServiceURL: serviceURL,
		HMACSecret: "internal-secret",
		CacheTTL:   time.Minute,
	}
}
