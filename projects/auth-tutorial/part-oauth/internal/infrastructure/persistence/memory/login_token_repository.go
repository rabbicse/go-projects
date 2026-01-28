package memory

import (
	"errors"
	"sync"

	authDomain "github.com/rabbicse/auth-service/internal/domain/aggregates/authentication"
)

type LoginTokenRepo struct {
	mu sync.Mutex
	m  map[string]*authDomain.LoginToken
}

func NewLoginTokenRepo() *LoginTokenRepo {
	return &LoginTokenRepo{m: map[string]*authDomain.LoginToken{}}
}

func (r *LoginTokenRepo) Save(t *authDomain.LoginToken) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[t.Value] = t
}

func (r *LoginTokenRepo) Find(value string) (*authDomain.LoginToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.m[value]
	if !ok {
		return nil, errors.New("not found")
	}
	return t, nil
}

func (r *LoginTokenRepo) MarkUsed(value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[value].Used = true
}
