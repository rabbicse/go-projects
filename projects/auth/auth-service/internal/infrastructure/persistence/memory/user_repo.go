package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/rabbicse/auth-service/internal/domain/common"
	"github.com/rabbicse/auth-service/internal/domain/user"
)

type UserRepository struct {
	mu    sync.RWMutex
	users map[string]*user.User
}

func NewUserRepository(seed []*user.User) *UserRepository {
	m := make(map[string]*user.User)
	for _, u := range seed {
		m[u.ID] = u
	}
	return &UserRepository{users: m}
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.users[id]
	if !ok {
		return nil, common.ErrNotFound
	}
	return u, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, common.ErrNotFound
}

func (r *UserRepository) Save(u *user.User) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[u.Username] = u
}

func (r *UserRepository) FindByUsername(username string) (*user.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}
