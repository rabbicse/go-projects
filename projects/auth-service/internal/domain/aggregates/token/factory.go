package token

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/shared"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
)

// TokenFactory is exported (starts with capital T)
type TokenFactory struct{}

// NewTokenFactory creates a new TokenFactory instance (exported)
func NewTokenFactory() *TokenFactory {
	return &TokenFactory{}
}

// CreateToken creates a new token with the specified parameters
func (f *TokenFactory) CreateToken(
	clientID string,
	userID string,
	scopes []string,
	tokenType string,
	expiresIn time.Duration,
	includeRefreshToken bool,
) (*Token, error) {

	// Create token type value object
	tokenTypeVO, err := valueobjects.NewTokenType(tokenType)
	if err != nil {
		return nil, err
	}

	// Delegate to the aggregate's NewToken function
	return NewToken(clientID, userID, scopes, tokenTypeVO, expiresIn, includeRefreshToken)
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

	// Create value objects
	tokenTypeVO, err := valueobjects.NewTokenType(tokenType)
	if err != nil {
		return nil, err
	}

	accessTokenVO, err := valueobjects.NewAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	expiry, err := valueobjects.NewTokenExpiry(expiresIn)
	if err != nil {
		return nil, err
	}

	clientIDVO, err := valueobjects.NewClientID(clientID)
	if err != nil {
		return nil, err
	}

	userIDVO, err := valueobjects.NewUserID(userID)
	if err != nil {
		return nil, err
	}

	var scopeObjs []valueobjects.Scope
	for _, scope := range scopes {
		s, err := valueobjects.NewScope(scope)
		if err != nil {
			return nil, err
		}
		scopeObjs = append(scopeObjs, *s)
	}

	token := &Token{
		accessToken: *accessTokenVO,
		tokenType:   tokenTypeVO,
		expiresIn:   *expiry,
		scopes:      scopeObjs,
		clientID:    *clientIDVO,
		userID:      userIDVO,
		issuedAt:    issuedAt,
		revokedAt:   revokedAt,
		events:      []shared.DomainEvent{},
	}

	// Add refresh token if present
	if refreshToken != "" {
		refreshTokenVO, err := valueobjects.NewRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}
		token.refreshToken = &refreshTokenVO
	}

	return token, nil
}
