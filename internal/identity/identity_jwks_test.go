package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"code.sarnas.ru/api-gateway/internal/config"
)

type rsaJWKEntry struct {
	kid string
	key *rsa.PrivateKey
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func jwksHandler(t *testing.T, entries []rsaJWKEntry) http.HandlerFunc {
	t.Helper()
	type jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	type set struct {
		Keys []jwk `json:"keys"`
	}
	var s set
	for _, e := range entries {
		s.Keys = append(s.Keys, jwk{
			Kty: "RSA",
			Kid: e.kid,
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(e.key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(e.key.E)).Bytes()),
		})
	}
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestResolve_ByJWKSProvider(t *testing.T) {
	lookup := newFakeLookup(map[string]string{"cml:uuid-jwks": activeUserJSON})
	lookupSrv := lookup.start(t)

	key := newRSAKey(t)
	jwks := httptest.NewServer(jwksHandler(t, []rsaJWKEntry{{kid: "cml-1", key: key}}))
	defer jwks.Close()

	cfg := config.IdentityConfig{
		Enabled:   true,
		Selection: []string{"cml"},
		UserLookup: config.IdentityUserLookupConfig{
			ServiceURL: lookupSrv.URL, HMACSecret: "internal-secret", CacheTTL: time.Minute,
		},
		Providers: []config.IdentityProviderConfig{{
			Name: "cml", Enabled: true, Algorithm: "RS256",
			JwksURL: jwks.URL, ValidateExp: true, SubjectProvider: "cml",
		}},
	}

	m, err := NewManager(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	token := signRS256(t, key, "cml-1", jwt.MapClaims{
		"sub": "uuid-jwks",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	u, err := m.Resolve(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.ID != 42 || u.Email != "partner@example.com" {
		t.Fatalf("unexpected user: %+v", u)
	}
}
