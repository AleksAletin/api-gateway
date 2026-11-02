package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"path/filepath"
	"strings"

	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"code.sarnas.ru/api-gateway/internal/config"
)

// letsEncryptStagingDirectory — ACME directory тестового CA Let's Encrypt.
const letsEncryptStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"

// workerPathPrefix — протокол воркеров. На публичном листенере он закрыт, но
// админские ручки того же префикса (approve/drain) остаются доступны: иначе
// одобрение слота невозможно без клиентского сертификата.
const workerPathPrefix = "/api/v1/workers/"

// buildCertManager собирает autocert.Manager по TLS-конфигу. При staging
// используется ACME staging directory и отдельный cache-подкаталог, чтобы
// staging-сертификаты не смешивались с production. tls.directory_url
// перекрывает выбор CA.
func buildCertManager(tls *config.TLSConfig) *autocert.Manager {
	cacheDir := tls.CacheDir
	if tls.Staging {
		cacheDir = filepath.Join(cacheDir, "staging")
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(exactDomains(tls.Domains)...),
		Cache:      autocert.DirCache(cacheDir),
		Email:      tls.Email,
	}

	directoryURL := tls.DirectoryURL
	if directoryURL == "" && tls.Staging {
		directoryURL = letsEncryptStagingDirectory
	}
	if directoryURL != "" {
		manager.Client = &acme.Client{DirectoryURL: directoryURL}
	}

	return manager
}

// exactDomains отбрасывает wildcard-шаблоны: их обслуживает certmagic через
// DNS-01, autocert такие имена выпускать не умеет.
func exactDomains(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if !strings.Contains(d, "*") {
			out = append(out, d)
		}
	}
	return out
}

// metricsOverHTTPHandler отдаёт /metrics и /metrics/prometheus напрямую
// (мидлварь внутри main проверяет metrics_allowed_ips), а остальные запросы
// отправляет на редирект HTTP→HTTPS. Нужно, чтобы дашборд и monitoring-glue
// могли скрейпить метрики по внутренней сети без TLS (autocert требует SNI и
// не работает по IP). Раньше по HTTP отдавался только /metrics, поэтому
// Prometheus-путь уезжал в https://<ip>:80 и скрейп падал.
func metricsOverHTTPHandler(main, redirect http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics", "/metrics/prometheus":
			main.ServeHTTP(w, r)
			return
		}
		redirect.ServeHTTP(w, r)
	})
}

// altSvcMiddleware объявляет HTTP/3 в ответах HTTP/1.1/2.
func altSvcMiddleware(next http.Handler, srv *http3.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = srv.SetQUICHeaders(w.Header())
		next.ServeHTTP(w, r)
	})
}

// isWorkerPath сообщает, относится ли путь к протоколу воркеров. Путь
// нормализуется, чтобы /api/v1/workers/../auth не считался разрешённым.
func isWorkerPath(p string) bool {
	segs := strings.Split(strings.Trim(path.Clean(p), "/"), "/")
	if len(segs) < 3 || segs[0] != "api" || segs[1] != "v1" {
		return false
	}
	// Lease-scoped секреты: токен аренды, не credential воркера.
	if segs[2] == "worker-leases" {
		return true
	}
	if segs[2] != "workers" {
		return false
	}
	switch {
	case len(segs) == 4 && segs[3] == "register":
		return true
	case len(segs) == 5 && segs[4] == "heartbeat":
		return true
	case len(segs) >= 6 && segs[4] == "leases":
		return true
	}
	// approve и drain — админские ручки, они остаются на публичном :443.
	return false
}

// workerOnlyHandler пропускает только /api/v1/workers/*, остальное отдаёт 404.
// Листенер с клиентскими сертификатами не должен становиться вторым входом к
// API: mTLS подтверждает хост, но не заменяет маршрутизацию по путям.
func workerOnlyHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWorkerPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// publicWorkerMutedHandler закрывает протокол воркеров на публичном
// листенере, когда поднят отдельный mTLS-листенер. Иначе mTLS остаётся
// необязательным: воркер мог бы прийти на :443 и обойти проверку сертификата.
func publicWorkerMutedHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWorkerPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// buildWorkerTLSConfig собирает TLS-конфиг отдельного листенера воркеров:
// тот же серверный сертификат, но обязательная проверка клиентского
// сертификата по указанному CA.
func buildWorkerTLSConfig(base *tls.Config, clientCAs *x509.CertPool) *tls.Config {
	tlsConfig := base.Clone()
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.ClientCAs = clientCAs
	tlsConfig.MinVersion = tls.VersionTLS12
	return tlsConfig
}

func (mp *MultiProxy) startTLS() error {
	tlsCfg := mp.config.Load().TLS

	certManager := buildCertManager(tlsCfg)
	autoTLS := certManager.TLSConfig()

	var (
		wildcardTLS      *tls.Config
		wildcardPatterns []string
		err              error
	)
	if tlsCfg.WildcardCertFile != "" {
		wildcardTLS, err = loadWildcardTLS(tlsCfg)
		if err != nil {
			return fmt.Errorf("wildcard certificate files: %w", err)
		}
		wildcardPatterns = wildcardDomains(tlsCfg.Domains)
		mp.logger.Info("Loaded wildcard certificate from files",
			zap.String("cert_file", tlsCfg.WildcardCertFile),
			zap.Strings("wildcard_domains", wildcardPatterns),
		)
	} else {
		wildcardMagic, stopWildcard, patterns, err := buildWildcardCertmagic(tlsCfg, mp.logger)
		if err != nil {
			return fmt.Errorf("wildcard certificates: %w", err)
		}
		if stopWildcard != nil {
			mp.certmagicStop = stopWildcard
		}
		wildcardPatterns = patterns
		if wildcardMagic != nil {
			wildcardTLS = wildcardMagic.TLSConfig()
		}
	}
	serverTLS := combineTLSConfig(autoTLS, wildcardTLS, wildcardPatterns)
	if err := applyTLSPolicy(serverTLS, tlsCfg); err != nil {
		return fmt.Errorf("TLS policy: %w", err)
	}

	// CA грузим до старта любого листенера: ошибка конфигурации mTLS должна
	// ронять процесс, а не оставлять воркеров без аутентификации.
	var workerClientCAs *x509.CertPool
	if tlsCfg.WorkerPort > 0 {
		pool, err := config.LoadClientCAPool(tlsCfg.WorkerClientCAFile)
		if err != nil {
			return fmt.Errorf("worker mTLS listener: %w", err)
		}
		workerClientCAs = pool
	}

	publicHandler := mp.wrapMiddleware(http.Handler(mp))
	if tlsCfg.WorkerPort > 0 {
		publicHandler = publicWorkerMutedHandler(publicHandler)
	}

	h3Cfg := mp.config.Load().HTTP3
	if h3Cfg.Enabled {
		h3TLS := serverTLS.Clone()
		h3TLS.NextProtos = []string{"h3"}
		h3Server := &http3.Server{
			Addr:      fmt.Sprintf(":%d", h3Cfg.Port),
			Port:      h3Cfg.Port,
			TLSConfig: h3TLS,
			Handler:   publicHandler,
		}
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: h3Cfg.Port})
		if err != nil {
			return fmt.Errorf("HTTP/3 listen: %w", err)
		}
		mp.http3Server = h3Server
		mp.http3Conn = conn
		publicHandler = altSvcMiddleware(publicHandler, h3Server)
		go func() {
			if err := h3Server.Serve(conn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				mp.logger.Error("HTTP/3 server error", zap.Error(err))
			}
		}()
		mp.logger.Info("Starting HTTP/3 server", zap.Int("udp_port", h3Cfg.Port))
	}

	tlsServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", tlsCfg.Port),
		Handler:      publicHandler,
		ReadTimeout:  mp.config.Load().Server.ReadTimeout,
		WriteTimeout: mp.config.Load().Server.WriteTimeout,
		IdleTimeout:  mp.config.Load().Server.IdleTimeout,
		TLSConfig:    serverTLS,
	}
	mp.httpsServer = tlsServer

	httpHandler := certManager.HTTPHandler(metricsOverHTTPHandler(publicHandler, mp.httpRedirectHandler()))
	httpServer := &http.Server{
		Addr:        fmt.Sprintf(":%d", tlsCfg.HTTPPort),
		Handler:     httpHandler,
		ReadTimeout: mp.config.Load().Server.ReadTimeout,
		IdleTimeout: mp.config.Load().Server.IdleTimeout,
	}
	mp.httpServer = httpServer

	var workerServer *http.Server
	if tlsCfg.WorkerPort > 0 {
		workerServer = &http.Server{
			Addr:         fmt.Sprintf(":%d", tlsCfg.WorkerPort),
			Handler:      workerOnlyHandler(mp),
			ReadTimeout:  mp.config.Load().Server.ReadTimeout,
			WriteTimeout: mp.config.Load().Server.WriteTimeout,
			IdleTimeout:  mp.config.Load().Server.IdleTimeout,
			TLSConfig:    buildWorkerTLSConfig(serverTLS, workerClientCAs),
		}
		mp.workerServer = workerServer
	}

	mp.logger.Info("Starting HTTPS proxy server with auto TLS",
		zap.Int("https_port", tlsCfg.Port),
		zap.Int("http_port", tlsCfg.HTTPPort),
		zap.Strings("domains", tlsCfg.Domains),
		zap.Strings("wildcard_domains", wildcardPatterns),
		zap.String("email", tlsCfg.Email),
		zap.String("cache_dir", tlsCfg.CacheDir),
		zap.Bool("staging", tlsCfg.Staging),
		zap.String("directory_url", tlsCfg.DirectoryURL),
		zap.Int("targets", len(mp.targets)),
		zap.Bool("worker_paths_on_public_listener", tlsCfg.WorkerPort == 0),
	)

	mp.logTargets()

	errCh := make(chan error, 3)

	go func() {
		mp.logger.Info("Starting HTTP server (ACME challenge + redirect)",
			zap.Int("port", tlsCfg.HTTPPort),
		)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	go func() {
		mp.logger.Info("Starting HTTPS server",
			zap.Int("port", tlsCfg.Port),
		)
		if err := tlsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTPS server error: %w", err)
		}
	}()

	if workerServer != nil {
		go func() {
			// Не логируем содержимое CA и ключей — только путь к файлу.
			mp.logger.Info("Starting worker mTLS server",
				zap.Int("port", tlsCfg.WorkerPort),
				zap.String("client_ca_file", tlsCfg.WorkerClientCAFile),
				zap.String("client_auth", "require_and_verify"),
				zap.String("path_prefix", workerPathPrefix),
			)
			if err := workerServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("worker mTLS server error: %w", err)
			}
		}()
	}

	return <-errCh
}
