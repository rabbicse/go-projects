package persistence

import (
	"sync"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
	"github.com/rabbicse/auth-service/internal/domain/repositories"
)

type InMemoryTokenRepository struct {
	accessTokens  map[string]*token.Token
	refreshTokens map[string]*token.Token
	mu            sync.RWMutex
	factory       *token.TokenFactory // Now this works because TokenFactory is exported
}

// NewInMemoryTokenRepository creates a new in-memory token repository
func NewInMemoryTokenRepository(factory *token.TokenFactory) repositories.TokenRepository {
	return &InMemoryTokenRepository{
		accessTokens:  make(map[string]*token.Token),
		refreshTokens: make(map[string]*token.Token),
		factory:       factory,
	}
}

// CreateToken creates a new token using the factory
func (r *InMemoryTokenRepository) CreateToken(
	clientID string,
	userID string,
	scopes []string,
	includeRefreshToken bool,
) (*token.Token, error) {

	return r.factory.CreateToken(
		clientID,
		userID,
		scopes,
		"Bearer",  // Default token type
		time.Hour, // Default expiry
		includeRefreshToken,
	)
}

// FindAccessToken retrieves a token by access token value
func (r *InMemoryTokenRepository) FindAccessToken(tokenStr string) (*token.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, exists := r.accessTokens[tokenStr]
	if !exists {
		return nil, &TokenNotFoundError{Token: tokenStr}
	}

	return t, nil
}

// FindRefreshToken retrieves a token by refresh token value
func (r *InMemoryTokenRepository) FindRefreshToken(tokenStr string) (*token.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, exists := r.refreshTokens[tokenStr]
	if !exists {
		return nil, &TokenNotFoundError{Token: tokenStr}
	}

	return t, nil
}

// SaveAccessToken persists an access token
func (r *InMemoryTokenRepository) SaveAccessToken(t *token.Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.accessTokens[t.AccessToken().Value] = t
	t.ClearEvents()
	return nil
}

// SaveRefreshToken persists a refresh token
func (r *InMemoryTokenRepository) SaveRefreshToken(t *token.Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if t.RefreshToken() != nil {
		r.refreshTokens[t.RefreshTokenValue()] = t
	}
	return nil
}

// RevokeAccessToken revokes an access token
func (r *InMemoryTokenRepository) RevokeAccessToken(tokenStr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.accessTokens, tokenStr)
	return nil
}

// RevokeRefreshToken revokes a refresh token
func (r *InMemoryTokenRepository) RevokeRefreshToken(tokenStr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.refreshTokens, tokenStr)
	return nil
}

// FindByUserID finds tokens for a specific user
func (r *InMemoryTokenRepository) FindByUserID(userID string, from, to time.Time) ([]*token.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*token.Token
	for _, t := range r.accessTokens {
		if t.UserID().Value() == userID {
			issuedAt := t.IssuedAt()
			if (issuedAt.Equal(from) || issuedAt.After(from)) &&
				(issuedAt.Equal(to) || issuedAt.Before(to)) {
				result = append(result, t)
			}
		}
	}

	return result, nil
}

// FindByClientID finds tokens for a specific client
func (r *InMemoryTokenRepository) FindByClientID(clientID string, from, to time.Time) ([]*token.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*token.Token
	for _, t := range r.accessTokens {
		if t.ClientID().Value() == clientID {
			issuedAt := t.IssuedAt()
			if (issuedAt.Equal(from) || issuedAt.After(from)) &&
				(issuedAt.Equal(to) || issuedAt.Before(to)) {
				result = append(result, t)
			}
		}
	}

	return result, nil
}

// DeleteExpired removes expired tokens
func (r *InMemoryTokenRepository) DeleteExpired(before time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for tokenStr, t := range r.accessTokens {
		if t.IsExpired() {
			delete(r.accessTokens, tokenStr)
		}
	}

	for tokenStr, t := range r.refreshTokens {
		if t.IsExpired() {
			delete(r.refreshTokens, tokenStr)
		}
	}

	return nil
}

// TokenNotFoundError is returned when a token is not found
type TokenNotFoundError struct {
	Token string
}

func (e TokenNotFoundError) Error() string {
	return "token not found: " + e.Token
}
