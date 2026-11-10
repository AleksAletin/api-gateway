package identity

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// fakeLookup отдаёт профили по (provider, subject) и считает обращения к
// subject-эндпоинту. Обращение к снятому с поддержки email-эндпоинту —
// регрессия, поэтому оно сразу роняет тест и учитывается счётчиком.
type fakeLookup struct {
	users       map[string]string // "<provider>:<subject>" -> JSON-тело data
	lookupFails bool              // subject-эндпоинт отвечает 503

	mu        sync.Mutex
	calls     []string
	emailHits int32
}

func newFakeLookup(users map[string]string) *fakeLookup {
	return &fakeLookup{users: users}
}

func (f *fakeLookup) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/internal/user-by-subject":
			key := r.URL.Query().Get("provider") + ":" + r.URL.Query().Get("subject")
			f.mu.Lock()
			f.calls = append(f.calls, key)
			f.mu.Unlock()
			if f.lookupFails {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			body, ok := f.users[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":` + body + `}`))
		case "/api/v1/internal/user-by-email":
			atomic.AddInt32(&f.emailHits, 1)
			t.Errorf("email lookup must never be called, got %s", r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected lookup path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeLookup) subjectCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

const (
	activeUserJSON   = `{"id":42,"email":"partner@example.com","full_name":"A","is_active":true,"roles":["viewer"]}`
	inactiveUserJSON = `{"id":43,"email":"inactive@example.com","is_active":false}`
)

// managerCfg — конфиг с одним enabled-провайдером, резолвящим только по субъекту.
func managerCfg(serviceURL string) config.IdentityConfig {
	return config.IdentityConfig{
		Enabled:   true,
		Selection: []string{"partner"},
		UserLookup: config.IdentityUserLookupConfig{
			ServiceURL: serviceURL, HMACSecret: "internal-secret", CacheTTL: time.Minute,
		},
		Providers: []config.IdentityProviderConfig{{
			Name: "partner", Enabled: true, Algorithm: "HS256",
			SecretKey: "partner-secret", ValidateExp: true,
			SubjectProvider: "cml",
		}},
	}
}

func TestResolve_ValidPartnerToken(t *testing.T) {
	lookup := newFakeLookup(map[string]string{"cml:uuid-1": activeUserJSON})
	srv := lookup.start(t)

	m, err := NewManager(managerCfg(srv.URL), zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	token := signHS256(t, "partner-secret", jwt.MapClaims{
		"sub": "uuid-1", "exp": time.Now().Add(time.Hour).Unix(),
	})
	u, err := m.Resolve(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.ID != 42 || u.Email != "partner@example.com" {
		t.Fatalf("unexpected user: %+v", u)
	}
	if got := lookup.subjectCalls(); len(got) != 1 || got[0] != "cml:uuid-1" {
		t.Fatalf("unexpected subject calls: %v", got)
	}
	if hits := atomic.LoadInt32(&lookup.emailHits); hits != 0 {
		t.Fatalf("email lookup must not be called, got %d", hits)
	}
}

func TestResolve_WrongSecret(t *testing.T) {
	lookup := newFakeLookup(nil)
	srv := lookup.start(t)
	m, _ := NewManager(managerCfg(srv.URL), zap.NewNop())

	token := signHS256(t, "our-secret", jwt.MapClaims{
		"sub": "uuid-1", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.Resolve(context.Background(), token); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestResolve_InactiveUser(t *testing.T) {
	lookup := newFakeLookup(map[string]string{"cml:uuid-inactive": inactiveUserJSON})
	srv := lookup.start(t)
	m, _ := NewManager(managerCfg(srv.URL), zap.NewNop())

	token := signHS256(t, "partner-secret", jwt.MapClaims{
		"sub": "uuid-inactive", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.Resolve(context.Background(), token); !errors.Is(err, ErrSubjectNotAvailable) {
		t.Fatalf("expected ErrSubjectNotAvailable for inactive user, got %v", err)
	}
}

// Токен с email активного пользователя, но без субъекта: вход по email удалён,
// поэтому такой токен не должен ни резолвиться, ни доходить до email-эндпоинта.
func TestResolve_EmailOnlyTokenRejected(t *testing.T) {
	lookup := newFakeLookup(map[string]string{"cml:uuid-1": activeUserJSON})
	srv := lookup.start(t)
	m, _ := NewManager(managerCfg(srv.URL), zap.NewNop())

	token := signHS256(t, "partner-secret", jwt.MapClaims{
		"email": "partner@example.com", "exp": time.Now().Add(time.Hour).Unix(),
	})
	u, err := m.Resolve(context.Background(), token)
	if !errors.Is(err, ErrSubjectNotAvailable) || u != nil {
		t.Fatalf("expected subject denial, got user=%+v err=%v", u, err)
	}
	if got := lookup.subjectCalls(); len(got) != 0 {
		t.Fatalf("subject lookup must not run without a subject, got %v", got)
	}
	if hits := atomic.LoadInt32(&lookup.emailHits); hits != 0 {
		t.Fatalf("email lookup must not be called, got %d", hits)
	}
}

func TestResolve_SelectionExcludesProvider(t *testing.T) {
	lookup := newFakeLookup(nil)
	srv := lookup.start(t)
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
	lookup := newFakeLookup(map[string]string{"cml:uuid-other": activeUserJSON})
	srv := lookup.start(t)
	cfg := managerCfg(srv.URL)
	cfg.Selection = nil
	cfg.Providers = append(cfg.Providers, config.IdentityProviderConfig{
		Name: "other", Enabled: true, Algorithm: "HS256",
		SecretKey: "other-secret", ValidateExp: true, SubjectProvider: "cml",
	})

	m, err := NewManager(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	// Токен второго (тоже enabled) провайдера должен резолвиться при пустом селекторе.
	token := signHS256(t, "other-secret", jwt.MapClaims{
		"sub": "uuid-other", "exp": time.Now().Add(time.Hour).Unix(),
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
	lookup := newFakeLookup(map[string]string{"cml:uuid-1": activeUserJSON})
	srv := lookup.start(t)
	cfg := managerCfg(srv.URL)
	cfg.Selection = []string{"partner"}
	cfg.Providers = append(cfg.Providers, config.IdentityProviderConfig{
		Name: "other", Enabled: true, Algorithm: "HS256",
		SecretKey: "other-secret", ValidateExp: true, SubjectProvider: "cml",
	})

	m, err := NewManager(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	// Токен невыбранного провайдера не должен приниматься выбранным.
	token := signHS256(t, "other-secret", jwt.MapClaims{
		"sub": "uuid-1", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := m.Resolve(context.Background(), token); err == nil {
		t.Fatal("expected error when token is signed by a non-selected provider")
	}
}

func TestNewManager_UnknownSelectionWarns(t *testing.T) {
	lookup := newFakeLookup(nil)
	srv := lookup.start(t)
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

// Провайдер без subject_provider не сможет резолвить пользователей: это ошибка
// старта, а не молчаливые 401 в рантайме.
func TestNewManager_RequiresSubjectProvider(t *testing.T) {
	lookup := newFakeLookup(nil)
	srv := lookup.start(t)
	cfg := managerCfg(srv.URL)
	cfg.Providers[0].SubjectProvider = "  "

	m, err := NewManager(cfg, zap.NewNop())
	if err == nil {
		t.Fatal("expected error for provider without subject_provider")
	}
	if m != nil {
		t.Fatal("expected nil manager for provider without subject_provider")
	}
	if !strings.Contains(err.Error(), "partner") || !strings.Contains(err.Error(), "subject_provider") {
		t.Fatalf("error must name the provider and the field, got: %v", err)
	}
}

// Отказ по любой причине (нет sub / нет маппинга / выключенный аккаунт / сбой
// lookup) окончателен: email-резолв не выполняется.
func TestResolve_SubjectFailureNeverFallsBackToEmail(t *testing.T) {
	scenarios := []struct {
		name         string
		claims       jwt.MapClaims
		users        map[string]string
		lookupFails  bool
		subjectCalls int
	}{
		{
			name:         "missing",
			claims:       jwt.MapClaims{"email": "partner@example.com"},
			subjectCalls: 0,
		},
		{
			name:         "not_found",
			claims:       jwt.MapClaims{"sub": "unknown-uuid", "email": "partner@example.com"},
			subjectCalls: 1,
		},
		{
			name:         "inactive",
			claims:       jwt.MapClaims{"sub": "uuid-inactive", "email": "partner@example.com"},
			users:        map[string]string{"cml:uuid-inactive": inactiveUserJSON},
			subjectCalls: 1,
		},
		{
			name:         "outage",
			claims:       jwt.MapClaims{"sub": "uuid-1", "email": "partner@example.com"},
			lookupFails:  true,
			subjectCalls: 1,
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			lookup := newFakeLookup(sc.users)
			lookup.lookupFails = sc.lookupFails
			srv := lookup.start(t)

			m, err := NewManager(managerCfg(srv.URL), zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}

			claims := jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}
			for k, v := range sc.claims {
				claims[k] = v
			}
			user, err := m.Resolve(context.Background(), signHS256(t, "partner-secret", claims))
			if !errors.Is(err, ErrSubjectNotAvailable) {
				t.Fatalf("expected ErrSubjectNotAvailable, got %v", err)
			}
			if user != nil {
				t.Fatalf("unexpected identity: %+v", user)
			}
			if hits := atomic.LoadInt32(&lookup.emailHits); hits != 0 {
				t.Fatalf("email fallback was called %d times", hits)
			}
			if got := lookup.subjectCalls(); len(got) != sc.subjectCalls {
				t.Fatalf("expected %d subject calls, got %v", sc.subjectCalls, got)
			}
		})
	}
}

// Два провайдера делят ключ, но у них разные namespace субъекта. Токен не
// должен «переезжать» в namespace другого провайдера: первый принявший подпись
// провайдер владеет токеном и отказывает.
func TestResolve_ForeignSubjectNamespaceDenied(t *testing.T) {
	lookup := newFakeLookup(map[string]string{"partner:uuid-1": activeUserJSON})
	srv := lookup.start(t)

	cfg := managerCfg(srv.URL)
	cfg.Selection = nil
	cfg.Providers = append(cfg.Providers, config.IdentityProviderConfig{
		Name: "second", Enabled: true, Algorithm: "HS256",
		SecretKey: "partner-secret", ValidateExp: true, SubjectProvider: "partner",
	})
	m, err := NewManager(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	token := signHS256(t, "partner-secret", jwt.MapClaims{
		"sub": "uuid-1", "exp": time.Now().Add(time.Hour).Unix(),
	})
	u, err := m.Resolve(context.Background(), token)
	if !errors.Is(err, ErrSubjectNotAvailable) || u != nil {
		t.Fatalf("expected denial, got user=%+v err=%v", u, err)
	}
	if got := lookup.subjectCalls(); len(got) != 1 || got[0] != "cml:uuid-1" {
		t.Fatalf("only the owning provider may be queried, got %v", got)
	}
}
