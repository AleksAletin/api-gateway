package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const sampleMetrics = `gateway_active_requests 3
gateway_rate_limit_denials_total 7
gateway_requests_total {"GET:/api/v1/auth/login:200": 12, "POST:/api/v1/auth/login:401": 1}
gateway_request_duration_ms {"GET:/api/v1/auth/login": 45}
`

func TestParseMetrics(t *testing.T) {
	m, err := parseMetrics([]byte(sampleMetrics))
	if err != nil {
		t.Fatalf("parseMetrics() error = %v", err)
	}
	if m.ActiveRequests != 3 {
		t.Errorf("ActiveRequests = %d, want 3", m.ActiveRequests)
	}
	if m.RateLimitDenials != 7 {
		t.Errorf("RateLimitDenials = %d, want 7", m.RateLimitDenials)
	}
	if got := m.RequestsTotal["GET:/api/v1/auth/login:200"]; got != 12 {
		t.Errorf("RequestsTotal[GET...] = %d, want 12", got)
	}
	if len(m.RequestsTotal) != 2 {
		t.Errorf("len(RequestsTotal) = %d, want 2", len(m.RequestsTotal))
	}
	if got := m.RequestDurationMS["GET:/api/v1/auth/login"]; got != 45 {
		t.Errorf("RequestDurationMS[GET...] = %d, want 45", got)
	}
	if !m.Loaded {
		t.Error("Loaded = false, want true")
	}
}

func TestParseMetricsUnknownPayload(t *testing.T) {
	if _, err := parseMetrics([]byte("<html>not metrics</html>")); err == nil {
		t.Fatal("parseMetrics() error = nil, want error for unrecognized payload")
	}
}

func TestScrapeMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sampleMetrics))
	}))
	defer srv.Close()

	m, err := ScrapeMetrics(srv.URL)
	if err != nil {
		t.Fatalf("ScrapeMetrics() error = %v", err)
	}
	if m.ActiveRequests != 3 {
		t.Errorf("ActiveRequests = %d, want 3", m.ActiveRequests)
	}
}

func TestScrapeMetricsNonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := ScrapeMetrics(srv.URL); err == nil {
		t.Fatal("ScrapeMetrics() error = nil, want error for non-200 response")
	}
}

func TestParseMetricsTargetRest(t *testing.T) {
	until := time.Now().Add(2 * time.Minute).Unix()
	payload := "gateway_active_requests 1\n" +
		"gateway_target_rest_until {\"api\": " + strconv.FormatInt(until, 10) + ", \"old\": 1000}\n" +
		"gateway_target_rest_reason {\"api\": \"503 (Retry-After)\"}\n"
	m, err := parseMetrics([]byte(payload))
	if err != nil {
		t.Fatalf("parseMetrics() error = %v", err)
	}
	if m.TargetRestUntil["api"] != until {
		t.Fatalf("TargetRestUntil[api] = %d, want %d", m.TargetRestUntil["api"], until)
	}
	resting := m.RestingTargets()
	if len(resting) != 1 || resting[0].Name != "api" {
		t.Fatalf("RestingTargets = %+v, want only api (old is in the past)", resting)
	}
	if resting[0].Reason != "503 (Retry-After)" {
		t.Fatalf("Reason = %q", resting[0].Reason)
	}
}
