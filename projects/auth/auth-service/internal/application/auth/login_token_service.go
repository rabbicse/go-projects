package auth

import (
	"errors"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/login"
)

var (
	ErrInvalidLoginToken = errors.New("invalid login token")
)

type LoginTokenService struct {
	repo interface {
		Save(*login.Token)
		Find(string) (*login.Token, error)
		MarkUsed(string)
	}
	clock func() time.Time
}

// Constructor
func NewLoginTokenService(
	repo interface {
		Save(*login.Token)
		Find(string) (*login.Token, error)
		MarkUsed(string)
	},
	clock func() time.Time,
) *LoginTokenService {
	return &LoginTokenService{
		repo:  repo,
		clock: clock,
	}
}

// internal/application/auth/login_token_service.go
func (s *LoginTokenService) UpgradeToMFA(tokenValue string) error {
	t, err := s.repo.Find(tokenValue)
	if err != nil {
		return err
	}
	t.AuthLevel = login.AuthMFAVerified
	s.repo.Save(t)
	return nil
}
