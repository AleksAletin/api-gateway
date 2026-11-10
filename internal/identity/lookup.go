package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"code.sarnas.ru/api-gateway/internal/config"
)

// Заголовки внутренней HMAC-подписи (совпадают с go-hmac-auth).
const (
	hmacUserIDHeader    = "X-User-ID"
	hmacSignatureHeader = "X-User-Signature"
	hmacTimestampHeader = "X-User-Timestamp"
)

// signHMACV2 повторяет схему подписи go-hmac-auth v2:
// hex(HMAC-SHA256(secret, userID + "\n" + METHOD + "\n" + path + "\n" + timestamp)).
// Реализовано локально, чтобы публичный api-gateway не зависел от приватного
// модуля github.com/X-didgital/go-hmac-auth. Должно совпадать с VerifyRequest
// на стороне passport-service.
func signHMACV2(userID, method, path, secret string, ts time.Time) (signature, timestamp string) {
	timestamp = strconv.FormatInt(ts.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(userID + "\n" + strings.ToUpper(method) + "\n" + path + "\n" + timestamp))
	return hex.EncodeToString(mac.Sum(nil)), timestamp
}

// User — минимальный профиль нашего пользователя, нужный шлюзу.
type User struct {
	ID       int
	Email    string
	FullName string
	IsActive bool
	Roles    []string
}

type lookupClient struct {
	baseURL string
	secret  string
	http    *http.Client
}

func newLookupClient(baseURL, secret string) *lookupClient {
	// Обрезаем завершающий "/", иначе baseURL+path даёт "//api/v1/...", а
	// подпись считается по "/api/v1/...", и passport отклоняет запрос (401).
	return &lookupClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		secret:  secret,
		http:    &http.Client{Timeout: 3 * time.Second},
	}
}

func (c *lookupClient) fetchBySubject(ctx context.Context, provider, subject string) (*User, error) {
	return c.doFetch(ctx, "/api/v1/internal/user-by-subject", url.Values{
		"provider": []string{provider},
		"subject":  []string{subject},
	})
}

func (c *lookupClient) doFetch(ctx context.Context, path string, q url.Values) (*User, error) {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("parse lookup url: %w", err)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create lookup request: %w", err)
	}

	ts := time.Now()
	sig, tsStr := signHMACV2("gateway", http.MethodGet, path, c.secret, ts)
	req.Header.Set(hmacUserIDHeader, "gateway")
	req.Header.Set(hmacSignatureHeader, sig)
	req.Header.Set(hmacTimestampHeader, tsStr)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("lookup request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lookup returned %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			ID       int      `json:"id"`
			Email    string   `json:"email"`
			FullName string   `json:"full_name"`
			IsActive bool     `json:"is_active"`
			Roles    []string `json:"roles"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode lookup response: %w", err)
	}

	return &User{
		ID:       body.Data.ID,
		Email:    body.Data.Email,
		FullName: body.Data.FullName,
		IsActive: body.Data.IsActive,
		Roles:    body.Data.Roles,
	}, nil
}

type cacheEntry struct {
	user      *User // nil = негативный результат (не найден)
	expiresAt time.Time
}

type lookupCache struct {
	mu    sync.RWMutex
	store map[string]cacheEntry
	ttl   time.Duration
}

func newLookupCache(ttl time.Duration) *lookupCache {
	return &lookupCache{store: make(map[string]cacheEntry), ttl: ttl}
}

func (c *lookupCache) get(key string) (*User, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.store[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.user, true
}

func (c *lookupCache) set(key string, u *User) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = cacheEntry{user: u, expiresAt: time.Now().Add(c.ttl)}
}

type resolver struct {
	client *lookupClient
	cache  *lookupCache
}

func newResolver(cfg config.IdentityUserLookupConfig) *resolver {
	return &resolver{
		client: newLookupClient(cfg.ServiceURL, cfg.HMACSecret),
		cache:  newLookupCache(cfg.CacheTTL),
	}
}

// bySubject возвращает (user, found, error). found=false при 404 или кэш-промахе.
func (r *resolver) bySubject(ctx context.Context, provider, subject string) (*User, bool, error) {
	return r.byKey(ctx, "s:"+provider+":"+subject, func() (*User, error) {
		return r.client.fetchBySubject(ctx, provider, subject)
	})
}

func (r *resolver) byKey(ctx context.Context, key string, fetch func() (*User, error)) (*User, bool, error) {
	if u, ok := r.cache.get(key); ok {
		if u == nil {
			return nil, false, nil
		}
		return u, true, nil
	}

	u, err := fetch()
	if err != nil {
		return nil, false, err
	}
	r.cache.set(key, u) // u может быть nil — негативное кэширование
	if u == nil {
		return nil, false, nil
	}
	return u, true, nil
}
