package memory

import (
	"context"
	"sync"

	"github.com/rabbicse/auth-service/internal/domain/authcode"
	"github.com/rabbicse/auth-service/internal/domain/common"
)

type AuthCodeRepository struct {
	mu    sync.Mutex
	codes map[string]*authcode.AuthorizationCode
}

func NewAuthCodeRepository() *AuthCodeRepository {
	return &AuthCodeRepository{
		codes: make(map[string]*authcode.AuthorizationCode),
	}
}

func (r *AuthCodeRepository) Save(ctx context.Context, code *authcode.AuthorizationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.codes[code.Code] = code
	return nil
}

func (r *AuthCodeRepository) Consume(ctx context.Context, code string) (*authcode.AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ac, ok := r.codes[code]
	if !ok {
		return nil, common.ErrNotFound
	}

	delete(r.codes, code) // 🔐 replay protection
	return ac, nil
}
