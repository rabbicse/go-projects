package memory

import (
	"sync"

	"github.com/rabbicse/auth-service/internal/domain"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/oauth"
)

type AuthCodeRepository struct {
	mu    sync.Mutex
	codes map[string]*oauth.AuthorizationCode
}

func NewAuthCodeRepository() *AuthCodeRepository {
	return &AuthCodeRepository{
		codes: make(map[string]*oauth.AuthorizationCode),
	}
}

func (r *AuthCodeRepository) Save(code *oauth.AuthorizationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.codes[code.Code] = code
	return nil
}

func (r *AuthCodeRepository) Get(code string) (*oauth.AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ac, ok := r.codes[code]
	if !ok {
		return nil, domain.ErrNotFound
	}

	delete(r.codes, code) // 🔐 replay protection
	return ac, nil
}
