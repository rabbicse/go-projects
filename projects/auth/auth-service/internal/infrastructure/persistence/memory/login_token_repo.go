package memory

import (
	"errors"
	"sync"

	logintoken "github.com/rabbicse/auth-service/internal/domain/login"
)

type LoginTokenRepo struct {
	mu sync.Mutex
	m  map[string]*logintoken.Token
}

func NewLoginTokenRepo() *LoginTokenRepo {
	return &LoginTokenRepo{m: map[string]*logintoken.Token{}}
}

func (r *LoginTokenRepo) Save(t *logintoken.Token) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[t.Value] = t
}

func (r *LoginTokenRepo) Find(value string) (*logintoken.Token, error) {
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
