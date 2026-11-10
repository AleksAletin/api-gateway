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

type provider struct {
	name            string
	validator       *jwtutil.JWTValidator
	emailClaim      string
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
			emailClaim:      pc.EmailClaim,
			subjectClaim:    pc.SubjectClaim,
			subjectProvider: pc.SubjectProvider,
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
func (m *Manager) Resolve(ctx context.Context, token string) (*User, error) {
	for _, p := range m.providers {
		claims, err := p.validator.ParseAndValidate(token)
		if err != nil {
			continue
		}
		if err := p.validator.ValidateClaims(claims); err != nil {
			continue
		}

		if p.subjectProvider != "" {
			if sub, _ := claims[p.subjectClaim].(string); strings.TrimSpace(sub) != "" {
				user, found, err := m.resolver.bySubject(ctx, p.subjectProvider, sub)
				if err != nil {
					m.logger.Warn("identity: subject lookup failed",
						zap.String("provider", p.name), zap.Error(err))
				} else if found && user != nil && user.IsActive {
					m.logger.Info("identity: external token resolved by subject",
						zap.String("provider", p.name), zap.Int("user_id", user.ID))
					return user, nil
				}
			}

			// A configured stable identity is authoritative. A miss, disabled
			// account, or lookup failure must not select another user by email.
			// Do not try another provider sharing the signing key either.
			return nil, errors.New("identity: subject is not available")
		}

		email, _ := claims[p.emailClaim].(string)
		email = strings.TrimSpace(email)
		if email == "" {
			continue
		}

		user, found, err := m.resolver.byEmail(ctx, email)
		if err != nil {
			m.logger.Warn("identity: user lookup failed",
				zap.String("provider", p.name), zap.Error(err))
			continue
		}
		if !found || user == nil || !user.IsActive {
			continue
		}

		m.logger.Info("identity: external token resolved",
			zap.String("provider", p.name), zap.Int("user_id", user.ID))
		return user, nil
	}

	return nil, errors.New("identity: no provider matched")
}
