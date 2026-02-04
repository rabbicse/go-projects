package memory

import (
	"sync"

	"github.com/rabbicse/auth-service/internal/domain"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
)

type TokenRepository struct {
	mu     sync.RWMutex
	tokens map[string]*token.Token
}

func NewTokenRepository() *TokenRepository {
	return &TokenRepository{
		tokens: make(map[string]*token.Token),
	}
}

func (r *TokenRepository) Save(t *token.Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tokens[t.AccessToken] = t
	return nil
}

func (r *TokenRepository) FindByAccessToken(accessToken string) (*token.Token, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	t, ok := r.tokens[accessToken]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return t, nil
}

func (r *TokenRepository) Revoke(accessToken string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.tokens, accessToken)
	return nil
}
