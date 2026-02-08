package token

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
)

type TokenIssuer interface {
	GenerateAccessToken(
		userID string,
		clientID string,
		scopes []string,
	) (string, time.Time, error)

	GenerateRefreshToken(
		userID string,
		clientID string,
	) (string, time.Time, error)

	GenerateIDToken(
		userID string,
		clientID string,
		email string,
	) (string, error)

	ValidateAccessToken(tokenStr string) (*valueobjects.AccessClaims, error)
}
