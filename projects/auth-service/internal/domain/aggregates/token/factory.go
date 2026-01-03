package token

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/shared"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
)

// TokenFactory creates and reconstitutes Token aggregates
type TokenFactory struct{}

func NewTokenFactory() *TokenFactory {
	return &TokenFactory{}
}

// Reconstitute recreates a Token aggregate from persistence
func (f *TokenFactory) Reconstitute(
	accessToken string,
	refreshToken string,
	tokenType string,
	expiresIn int,
	scopes []string,
	clientID string,
	userID string,
	issuedAt time.Time,
	revokedAt *time.Time,
) (*Token, error) {

	accessTokenVO, err := valueobjects.NewAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	tokenTypeVO, err := valueobjects.NewTokenType(tokenType)
	if err != nil {
		return nil, err
	}

	expiry, err := valueobjects.NewTokenExpiry(expiresIn)
	if err != nil {
		return nil, err
	}

	cid, err := valueobjects.NewClientID(clientID)
	if err != nil {
		return nil, err
	}

	uid, err := valueobjects.NewUserID(userID)
	if err != nil {
		return nil, err
	}

	var scopeObjs []valueobjects.Scope
	for _, scope := range scopes {
		s, err := valueobjects.NewScope(scope)
		if err != nil {
			return nil, err
		}
		scopeObjs = append(scopeObjs, s)
	}

	token := &Token{
		accessToken: accessTokenVO,
		tokenType:   tokenTypeVO,
		expiresIn:   expiry,
		scopes:      scopeObjs,
		clientID:    cid,
		userID:      uid,
		issuedAt:    issuedAt,
		revokedAt:   revokedAt,
		events:      []shared.DomainEvent{},
	}

	// Reconstitute refresh token if present
	if refreshToken != "" {
		refreshTokenVO, err := valueobjects.NewRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}
		token.refreshToken = &refreshTokenVO
	}

	return token, nil
}
