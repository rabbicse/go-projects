package authentication

import (
	"errors"
	"time"

	authDomain "github.com/rabbicse/auth-service/internal/domain/aggregates/authentication"
	"github.com/rabbicse/auth-service/pkg/helpers"
)

var (
	ErrInvalidLoginToken = errors.New("invalid login token")
)

type LoginTokenService struct {
	repo authDomain.LoginTokenRepository
}

// Constructor
func NewLoginTokenService(
	repo authDomain.LoginTokenRepository,
) *LoginTokenService {
	return &LoginTokenService{
		repo: repo,
	}
}

func (s *LoginTokenService) Issue(userID string) (string, error) {
	token := &authDomain.LoginToken{
		Value:     helpers.RandomToken(), // 256-bit cryptographic random
		UserID:    userID,
		ExpiresAt: time.Now().Add(2 * time.Minute),
		Used:      false,
	}

	s.repo.Save(token)
	return token.Value, nil
}
