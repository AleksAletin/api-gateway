package proxy

import (
	"net/http"
	"testing"
	"time"

	"go.uber.org/zap"

	"code.sarnas.ru/api-gateway/internal/config"
)

func restCandidate(name string, rest *config.RestConfig) *TargetProxy {
	return &TargetProxy{
		config:           &config.TargetConfig{Name: name, Rest: rest},
		healthy:          true,
		cbState:          stateClosed,
		failureThreshold: defaultFailureThreshold,
		cbTimeout:        defaultCBTimeout,
	}
}

func restConfig(base, max time.Duration) *config.RestConfig {
	return &config.RestConfig{Enabled: true, Base: base, Max: max}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{"empty", "", 0, false},
		{"seconds", "120", 120 * time.Second, true},
		{"zero", "0", 0, true},
		{"negative", "-5", 0, false},
		{"garbage", "soon", 0, false},
		{"http date", now.Add(90 * time.Second).UTC().Format(http.TimeFormat), 90 * time.Second, true},
		{"past http date", now.Add(-time.Minute).UTC().Format(http.TimeFormat), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tc.value, now)
			if ok != tc.ok {
				t.Fatalf("ok=%v, want %v", ok, tc.ok)
			}
			if ok && (got < tc.want-time.Second || got > tc.want+time.Second) {
				t.Fatalf("d=%v, want ~%v", got, tc.want)
			}
		})
	}
}

func TestStartRestHonorsRetryAfter(t *testing.T) {
	tp := restCandidate("a", restConfig(time.Minute, 30*time.Minute))
	until, reason := tp.startRest(http.StatusServiceUnavailable, "120")
	want := time.Now().Add(120 * time.Second)
	if until.Before(want.Add(-2*time.Second)) || until.After(want.Add(2*time.Second)) {
		t.Fatalf("until=%v, want ~%v", until, want)
	}
	if reason != "503 (Retry-After)" {
		t.Fatalf("reason=%q", reason)
	}
	if !tp.resting() {
		t.Fatal("target should be resting")
	}
}

func TestStartRestCapsRetryAfter(t *testing.T) {
	tp := restCandidate("a", restConfig(time.Minute, 5*time.Minute))
	until, _ := tp.startRest(http.StatusTooManyRequests, "3600")
	want := time.Now().Add(5 * time.Minute)
	if until.Before(want.Add(-2*time.Second)) || until.After(want.Add(2*time.Second)) {
		t.Fatalf("until=%v, want capped ~%v", until, want)
	}
}

func TestStartRestEscalatesWithoutRetryAfter(t *testing.T) {
	tp := restCandidate("a", restConfig(time.Minute, 30*time.Minute))
	base := time.Now()
	for i, want := range []time.Duration{1, 2, 4, 8} {
		until, reason := tp.startRest(http.StatusTooManyRequests, "")
		wantUntil := base.Add(time.Duration(want) * time.Minute)
		if until.Before(wantUntil.Add(-2*time.Second)) || until.After(wantUntil.Add(2*time.Second)) {
			t.Fatalf("step %d: until=%v, want ~%v", i, until, wantUntil)
		}
		if reason != "429" {
			t.Fatalf("step %d: reason=%q, want plain status", i, reason)
		}
	}
}

func TestStartRestEscalationCapped(t *testing.T) {
	tp := restCandidate("a", restConfig(time.Minute, 3*time.Minute))
	for i := 0; i < 5; i++ {
		tp.startRest(http.StatusServiceUnavailable, "")
	}
	until, _ := tp.startRest(http.StatusServiceUnavailable, "")
	if d := time.Until(until); d > 3*time.Minute+2*time.Second {
		t.Fatalf("rest %v exceeds max 3m", d)
	}
}

func TestStartRestResetsAfterQuietPeriod(t *testing.T) {
	tp := restCandidate("a", restConfig(time.Minute, 30*time.Minute))
	tp.restCount = 5
	tp.restReason = "429"
	tp.lastRestAt = time.Now().Add(-31 * time.Minute)
	until, _ := tp.startRest(http.StatusTooManyRequests, "")
	want := time.Now().Add(time.Minute)
	if until.Before(want.Add(-2*time.Second)) || until.After(want.Add(2*time.Second)) {
		t.Fatalf("until=%v, want reset to base ~%v", until, want)
	}
	if tp.restCount != 1 {
		t.Fatalf("restCount=%d, want 1 after reset", tp.restCount)
	}
}

func TestPickTargetSkipsResting(t *testing.T) {
	a := restCandidate("a", restConfig(time.Minute, 30*time.Minute))
	b := restCandidate("b", restConfig(time.Minute, 30*time.Minute))
	a.restUntil = time.Now().Add(time.Minute)
	rc := lbRoute("round_robin", a, b)
	for i := 0; i < 10; i++ {
		if got := rc.pickTarget(false); got != b {
			t.Fatalf("picked %s, want b (a is resting)", got.config.Name)
		}
	}
}

func TestPickTargetAllRestingPicksEarliest(t *testing.T) {
	a := restCandidate("a", restConfig(time.Minute, 30*time.Minute))
	b := restCandidate("b", restConfig(time.Minute, 30*time.Minute))
	a.restUntil = time.Now().Add(5 * time.Minute)
	b.restUntil = time.Now().Add(time.Minute)
	rc := lbRoute("round_robin", a, b)
	if got := rc.pickTarget(false); got != b {
		t.Fatalf("picked %s, want b (returns earliest)", got.config.Name)
	}
}

func TestPickTargetSingleRestingStillServes(t *testing.T) {
	a := restCandidate("a", restConfig(time.Minute, 30*time.Minute))
	a.restUntil = time.Now().Add(time.Minute)
	rc := lbRoute("round_robin", a)
	if got := rc.pickTarget(false); got != a {
		t.Fatal("single resting target should still serve instead of 503")
	}
}

func TestPickTargetExpiredRestIsEligible(t *testing.T) {
	a := restCandidate("a", restConfig(time.Minute, 30*time.Minute))
	a.restUntil = time.Now().Add(-time.Minute)
	rc := lbRoute("round_robin", a)
	if got := rc.pickTarget(false); got != a {
		t.Fatal("expired rest should not exclude the target")
	}
}

func TestNoteTargetRest(t *testing.T) {
	mp := &MultiProxy{metrics: NewMetrics(false), logger: zap.NewNop()}
	resp := func(status int, retryAfter string) *http.Response {
		r := &http.Response{StatusCode: status, Header: http.Header{}}
		if retryAfter != "" {
			r.Header.Set("Retry-After", retryAfter)
		}
		return r
	}

	off := restCandidate("off", nil)
	mp.noteTargetRest(off, resp(429, ""))
	if off.resting() {
		t.Fatal("rest disabled: target must not rest")
	}

	on := restCandidate("on", restConfig(time.Minute, 30*time.Minute))
	mp.noteTargetRest(on, resp(200, ""))
	if on.resting() {
		t.Fatal("200 must not trigger rest")
	}

	mp.noteTargetRest(on, resp(429, "60"))
	if !on.resting() {
		t.Fatal("429 must trigger rest when enabled")
	}
}

func TestStickySkipsResting(t *testing.T) {
	a := restCandidate("a", restConfig(time.Minute, 30*time.Minute))
	b := restCandidate("b", restConfig(time.Minute, 30*time.Minute))
	a.restUntil = time.Now().Add(time.Minute)
	rc := lbRoute("sticky", a, b)
	mp := &MultiProxy{}

	req, _ := http.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: stickyCookieName, Value: signSticky("a")})
	rec := &fakeResponseWriter{header: http.Header{}}
	if got := mp.pickTargetForRequest(rc, false, req, rec); got != b {
		names := map[*TargetProxy]string{a: "a", b: "b"}
		t.Fatalf("sticky picked resting target %s, want b", names[got])
	}
}

// fakeResponseWriter — минимальный ResponseWriter для теста sticky.
type fakeResponseWriter struct {
	header http.Header
}

func (f *fakeResponseWriter) Header() http.Header         { return f.header }
func (f *fakeResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeResponseWriter) WriteHeader(int)             {}
