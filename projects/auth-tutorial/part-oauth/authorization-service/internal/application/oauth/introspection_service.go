package oauth

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
)

type IntrospectionService struct {
	tokenRepo token.TokenRepository
	clock     func() time.Time
}

func NewIntrospectionService(
	tokenRepo token.TokenRepository,
	clock func() time.Time,
) *IntrospectionService {
	return &IntrospectionService{
		tokenRepo: tokenRepo,
		clock:     clock,
	}
}

func (s *IntrospectionService) Introspect(accessToken string) (*token.Token, bool) {
	t, err := s.tokenRepo.FindByAccessToken(accessToken)
	if err != nil {
		return nil, false
	}

	if t.IsExpired(s.clock()) {
		return nil, false
	}

	return t, true
}
