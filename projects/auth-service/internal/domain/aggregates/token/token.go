package token

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/shared"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
)

type Token struct {
	// Token fields would be defined here
	// Token is the Aggregate Root for Token bounded context
	accessToken  valueobjects.AccessToken
	refreshToken *valueobjects.RefreshToken
	tokenType    valueobjects.TokenType
	expiresIn    valueobjects.TokenExpiry
	scopes       []valueobjects.Scope
	clientID     valueobjects.ClientID
	userID       valueobjects.UserID
	issuedAt     time.Time
	revokedAt    *time.Time

	events []shared.DomainEvent
}
