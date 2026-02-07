package token

import "time"

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
}
