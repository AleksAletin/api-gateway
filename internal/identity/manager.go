package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"code.sarnas.ru/api-gateway/internal/config"
	"code.sarnas.ru/api-gateway/internal/jwtutil"
)

var (
	// ErrSubjectNotAvailable — у провайдера с валидной подписью не удалось
	// установить пользователя по (subject_provider, sub). Отдельная ошибка,
	// чтобы отказ по идентичности был отличим от «токен не наш».
	ErrSubjectNotAvailable = errors.New("identity: subject identity is not verified")
	// ErrNoProviderMatched — ни один провайдер не принял токен.
	ErrNoProviderMatched = errors.New("identity: no provider matched")
)

type provider struct {
	name            string
	validator       *jwtutil.JWTValidator
	subjectClaim    string
	subjectProvider string
}

// Manager перебирает доверенные внешние провайдеры и резолвит нашего пользователя.
type Manager struct {
	providers []provider
	resolver  *resolver
	logger    *zap.Logger
}

func NewManager(cfg config.IdentityConfig, logger *zap.Logger) (*Manager, error) {
	selected := make(map[string]bool, len(cfg.Selection))
	for _, name := range cfg.Selection {
		selected[name] = true
	}

	enabled := make(map[string]bool, len(cfg.Providers))
	for _, pc := range cfg.Providers {
		if pc.Enabled {
			enabled[pc.Name] = true
		}
	}

	if len(cfg.Selection) > 0 {
		for _, name := range cfg.Selection {
			if !enabled[name] {
				logger.Warn("identity: selection entry does not match an enabled provider",
					zap.String("provider", name))
			}
		}
	}

	var providers []provider
	for _, pc := range cfg.Providers {
		if !pc.Enabled {
			continue
		}
		if len(cfg.Selection) > 0 && !selected[pc.Name] {
			continue
		}
		if pc.SubjectClaim == "" {
			pc.SubjectClaim = "sub"
		}
		// Идентичность устанавливается только по (subject_provider, sub):
		// провайдер без namespace субъекта не сможет никого резолвить и молча
		// отдавал бы 401 всему трафику, поэтому это ошибка старта, а не
		// деградация в рантайме.
		if strings.TrimSpace(pc.SubjectProvider) == "" {
			return nil, fmt.Errorf("identity provider %s: subject_provider is required", pc.Name)
		}
		var (
			v   *jwtutil.JWTValidator
			err error
		)
		if pc.JwksURL != "" {
			v, err = jwtutil.NewJWKSValidator(
				pc.JwksURL, pc.Algorithm,
				pc.ValidateExp, pc.ValidateIss, pc.ExpectedIss,
				logger,
			)
		} else {
			v, err = jwtutil.NewJWTValidator(
				pc.SecretKey, pc.Algorithm,
				pc.ValidateExp, pc.ValidateIss, pc.ExpectedIss,
				false, "", pc.PublicKeyFile,
			)
		}
		if err != nil {
			return nil, fmt.Errorf("identity provider %s: %w", pc.Name, err)
		}
		providers = append(providers, provider{
			name:            pc.Name,
			validator:       v,
			subjectClaim:    pc.SubjectClaim,
			subjectProvider: strings.TrimSpace(pc.SubjectProvider),
		})
	}

	if len(providers) == 0 {
		return nil, errors.New("identity: no providers selected")
	}

	return &Manager{
		providers: providers,
		resolver:  newResolver(cfg.UserLookup),
		logger:    logger,
	}, nil
}

// Resolve проверяет токен по выбранным провайдерам и возвращает нашего пользователя.
//
// Идентичность внешнего токена устанавливается только по (subject_provider, sub).
// Claim email здесь не используется: его контролирует тот, кто выпустил токен, и
// резолв по email позволил бы войти под любым активным пользователем с известным
// адресом. Провайдер, чья подпись прошла, владеет токеном: он либо резолвит
// пользователя, либо отказывает — перебирать дальше нельзя, иначе sub одного
// namespace можно было бы предъявить в namespace другого провайдера.
func (m *Manager) Resolve(ctx context.Context, token string) (*User, error) {
	for _, p := range m.providers {
		claims, err := p.validator.ParseAndValidate(token)
		if err != nil {
			continue
		}
		if err := p.validator.ValidateClaims(claims); err != nil {
			continue
		}

		subject, _ := claims[p.subjectClaim].(string)
		subject = strings.TrimSpace(subject)
		if subject == "" {
			m.logger.Warn("identity: token has no subject claim",
				zap.String("provider", p.name),
				zap.String("claim", p.subjectClaim))
			return nil, fmt.Errorf("%w: subject claim %q is missing", ErrSubjectNotAvailable, p.subjectClaim)
		}

		user, found, err := m.resolver.bySubject(ctx, p.subjectProvider, subject)
		if err != nil {
			m.logger.Warn("identity: subject lookup failed",
				zap.String("provider", p.name),
				zap.String("subject_provider", p.subjectProvider),
				zap.Error(err))
			return nil, fmt.Errorf("%w: subject lookup failed", ErrSubjectNotAvailable)
		}
		if !found || user == nil {
			m.logger.Warn("identity: subject is not mapped",
				zap.String("provider", p.name),
				zap.String("subject_provider", p.subjectProvider),
				zap.String("subject", subject))
			return nil, fmt.Errorf("%w: subject is not mapped", ErrSubjectNotAvailable)
		}
		if !user.IsActive {
			m.logger.Warn("identity: subject maps to an inactive user",
				zap.String("provider", p.name),
				zap.String("subject_provider", p.subjectProvider),
				zap.String("subject", subject),
				zap.Int("user_id", user.ID))
			return nil, fmt.Errorf("%w: subject maps to an inactive user", ErrSubjectNotAvailable)
		}

		m.logger.Info("identity: external token resolved by subject",
			zap.String("provider", p.name), zap.Int("user_id", user.ID))
		return user, nil
	}

	return nil, ErrNoProviderMatched
}
