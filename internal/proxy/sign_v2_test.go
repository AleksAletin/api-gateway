package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"code.sarnas.ru/api-gateway/internal/config"
	"go.uber.org/zap"
)

func TestPerRouteV2SignatureBindsUserMethodPathAndTime(t *testing.T) {
	cfg := &config.Config{}
	cfg.JWT.Algorithm = "HS256"
	cfg.JWT.SecretKey = "jwt-test"
	cfg.Permissions.APIKey = "test-key"
	mp, err := NewMultiProxy(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("post", "/api/reports/own?campaign=25", nil)
	mp.applySignV3ForUser(r, "164", &config.RoutingRule{SignV2: true})
	stamp := r.Header.Get("X-User-Timestamp")
	unix, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || time.Since(time.Unix(unix, 0)) > 2*time.Second {
		t.Fatal("missing fresh timestamp", stamp)
	}
	if got := r.Header.Get("X-User-ID"); got != "164" {
		t.Fatal("v2 must set X-User-ID to the signed id, got", got)
	}
	mac := hmac.New(sha256.New, []byte("test-key"))
	mac.Write([]byte("164\nPOST\n/api/reports/own\n" + stamp))
	if r.Header.Get("X-User-Signature") != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("signature does not match monitoring v2 contract")
	}
	if r.Header.Get("X-Service-ID") != "" {
		t.Fatal("v3 identity leaked to v2 route")
	}
}
