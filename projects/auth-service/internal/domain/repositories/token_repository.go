package repositories

import (
	"go/token"
	"time"
)

// TokenRepository defines the interface for Token aggregate persistence
type TokenRepository interface {
	// FindAccessToken retrieves a token by access token value
	FindAccessToken(token string) (*token.Token, error)

	// FindRefreshToken retrieves a token by refresh token value
	FindRefreshToken(token string) (*token.Token, error)

	// SaveAccessToken persists an access token aggregate
	SaveAccessToken(token *token.Token) error

	// SaveRefreshToken persists a refresh token aggregate
	SaveRefreshToken(token *token.Token) error

	// RevokeAccessToken revokes an access token
	RevokeAccessToken(token string) error

	// RevokeRefreshToken revokes a refresh token
	RevokeRefreshToken(token string) error

	// FindByUserID finds tokens for a specific user
	FindByUserID(userID string, from, to time.Time) ([]*token.Token, error)

	// FindByClientID finds tokens for a specific client
	FindByClientID(clientID string, from, to time.Time) ([]*token.Token, error)

	// DeleteExpired removes expired tokens
	DeleteExpired(before time.Time) error
}
