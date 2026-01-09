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
