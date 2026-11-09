package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
)

// stickyCookieName — cookie привязки клиента к таргету при lb_policy: sticky.
const stickyCookieName = "xg_target"

// stickyKey подписывает значение cookie. Ключ живёт в памяти процесса:
// клиент не может ни подделать значение, ни прочитать имя внутреннего
// таргета из base64, а после рестарта все привязки сбрасываются — это
// осознанно (таргеты могли переехать).
var stickyKey = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("proxy: cannot generate sticky cookie key: " + err.Error())
	}
	return b
}()

func stickyMAC(name string) []byte {
	mac := hmac.New(sha256.New, stickyKey)
	mac.Write([]byte(name))
	return mac.Sum(nil)
}

// signSticky кодирует имя таргета: base64url(name).hex(HMAC(name)).
func signSticky(name string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(name)) + "." +
		hex.EncodeToString(stickyMAC(name))
}

// parseSticky возвращает имя таргета из cookie. ok=false для мусора,
// подделки и имени с неверной подписью.
func parseSticky(value string) (string, bool) {
	raw, sig, found := splitSticky(value)
	if !found {
		return "", false
	}
	nameBytes, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", false
	}
	want, err := hex.DecodeString(sig)
	if err != nil || !hmac.Equal(want, stickyMAC(string(nameBytes))) {
		return "", false
	}
	return string(nameBytes), true
}

func splitSticky(value string) (raw, sig string, ok bool) {
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == '.' {
			if i == 0 || i == len(value)-1 {
				return "", "", false
			}
			return value[:i], value[i+1:], true
		}
	}
	return "", "", false
}

// targetByName ищет таргет пула по имени.
func (rc *RouteConfig) targetByName(name string) *TargetProxy {
	if rc == nil {
		return nil
	}
	for i, tp := range rc.Targets {
		if tp.config.Name == name && rc.weights[i] > 0 {
			return tp
		}
	}
	return nil
}

// pickTargetForRequest — выбор таргета с учётом sticky-привязки. Если политика
// не sticky — обычный pickTarget. Для sticky: валидная cookie и здоровый
// таргет из этого пула выигрывают, иначе взвешенный round_robin и новая cookie.
func (mp *MultiProxy) pickTargetForRequest(rc *RouteConfig, cbEnabled bool, r *http.Request, w http.ResponseWriter) *TargetProxy {
	if rc == nil {
		return nil
	}
	if rc.lbPolicy == "sticky" {
		if c, err := r.Cookie(stickyCookieName); err == nil {
			if name, ok := parseSticky(c.Value); ok {
				if tp := rc.targetByName(name); tp != nil && !tp.resting() && tp.eligible(cbEnabled) && tp.acquire(cbEnabled) {
					return tp
				}
			}
		}
	}
	tp := rc.pickTarget(cbEnabled, mp.clientIP(r))
	if tp != nil && rc.lbPolicy == "sticky" {
		http.SetCookie(w, &http.Cookie{
			Name:     stickyCookieName,
			Value:    signSticky(tp.config.Name),
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil,
		})
	}
	return tp
}
