package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// «Отдых» таргета (идея yetone/magpie, issue #52): ответ 429 или 503 от
// таргета мягко выводит его из выбора в пуле на время. С Retry-After — ровно
// на указанное (потолок rest.max), без него — эскалация от rest.base
// удвоением (потолок rest.max, сброс счёта после тихого периода max).
// Отдых не трогает circuit breaker и health check: таргет остаётся
// «здоровым», просто пул его временно пропускает. Если отдыхают все
// кандидаты, запрос идёт тому, кто вернётся раньше всех, а не 503.

// startRest отмечает таргет отдыхающим и возвращает момент возврата и
// причину. Вызывается из ModifyResponse при 429/503, если rest.enabled.
func (tp *TargetProxy) startRest(status int, retryAfter string) (time.Time, string) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	cfg := tp.config.Rest
	max := cfg.EffectiveMax()
	now := time.Now()

	var d time.Duration
	var reason string
	if ra, ok := parseRetryAfter(retryAfter, now); ok {
		d = min(ra, max)
		reason = strconv.Itoa(status) + " (Retry-After)"
	} else {
		// Эскалация: base, 2*base, 4*base… до max; после тихого периода
		// (с прошлого отдыха прошло больше max) счёт начинается заново.
		if tp.restReason == "" || now.Sub(tp.lastRestAt) > max {
			tp.restCount = 0
		}
		d = min(cfg.EffectiveBase()<<min(tp.restCount, 20), max)
		tp.restCount++
		reason = strconv.Itoa(status)
	}

	tp.restUntil = now.Add(d)
	tp.lastRestAt = now
	tp.restReason = reason
	return tp.restUntil, reason
}

// resting сообщает, отдыхает ли таргет сейчас.
func (tp *TargetProxy) resting() bool {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return time.Now().Before(tp.restUntil)
}

// restSnapshot возвращает момент возврата, причину и флаг «отдыхает сейчас».
func (tp *TargetProxy) restSnapshot() (time.Time, string, bool) {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.restUntil, tp.restReason, time.Now().Before(tp.restUntil)
}

// parseRetryAfter разбирает заголовок Retry-After: либо секунды, либо
// HTTP-дату. ok=false — заголовка нет или он неразборчив.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0, false
		}
		return time.Duration(n) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
	}
	return 0, false
}

// noteTargetRest выводит таргет в отдых после 429/503, если у таргета
// включён rest. Отдых применяется независимо от того, есть ли в пуле другие
// кандидаты: случай «все отдыхают» разрешает pickEarliestResting.
func (mp *MultiProxy) noteTargetRest(tp *TargetProxy, resp *http.Response) {
	rest := tp.config.Rest
	if rest == nil || !rest.Enabled {
		return
	}
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
		return
	}
	until, reason := tp.startRest(resp.StatusCode, resp.Header.Get("Retry-After"))
	mp.metrics.SetTargetRest(tp.config.Name, until, reason)
	mp.logger.Info("Target is resting after upstream response",
		zap.String("target", tp.config.Name),
		zap.Int("status", resp.StatusCode),
		zap.String("reason", reason),
		zap.Time("until", until),
	)
}

// pickEarliestResting возвращает отдыхающего кандидата, который вернётся
// раньше всех, — запасной вариант, когда свободных таргетов в пуле нет
// («все отдыхают» → не отдавать 503, пока есть живой отдыхающий таргет).
func (rc *RouteConfig) pickEarliestResting(cbEnabled bool) *TargetProxy {
	var best *TargetProxy
	var bestUntil time.Time
	for i, tp := range rc.Targets {
		if rc.weights[i] <= 0 {
			continue
		}
		until, _, ok := tp.restSnapshot()
		if !ok || !tp.eligible(cbEnabled) {
			continue
		}
		if best == nil || until.Before(bestUntil) {
			best, bestUntil = tp, until
		}
	}
	if best != nil && best.acquire(cbEnabled) {
		return best
	}
	return nil
}
