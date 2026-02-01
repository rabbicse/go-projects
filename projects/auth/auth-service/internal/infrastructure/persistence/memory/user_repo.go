package memory

import (
	"errors"
	"sync"

	"github.com/rabbicse/auth-service/internal/domain/common"
	"github.com/rabbicse/auth-service/internal/domain/user"
)

type UserRepository struct {
	mu           sync.RWMutex
	usersByID    map[string]*user.User
	usersByName  map[string]*user.User
	usersByEmail map[string]*user.User
}

func NewUserRepository(seed []*user.User) *UserRepository {
	m := make(map[string]*user.User)
	usersByID := make(map[string]*user.User)
	usersByEmail := make(map[string]*user.User)

	for _, u := range seed {
		m[u.ID] = u
		usersByID[u.ID] = u
		usersByEmail[u.Email] = u
	}
	return &UserRepository{usersByID: usersByID, usersByName: m, usersByEmail: usersByEmail}
}

func (r *UserRepository) Save(u *user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.usersByName[u.Username] = u
	r.usersByID[u.ID] = u
	r.usersByEmail[u.Email] = u

	return nil
}

func (r *UserRepository) FindByUsername(username string) (*user.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.usersByName[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (r *UserRepository) FindByID(id string) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.usersByID[id]
	if !ok {
		return nil, common.ErrNotFound
	}
	return u, nil
}

func (r *UserRepository) FindByEmail(email string) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.usersByEmail[email]
	if !ok {
		return nil, common.ErrNotFound
	}
	return u, nil
}
