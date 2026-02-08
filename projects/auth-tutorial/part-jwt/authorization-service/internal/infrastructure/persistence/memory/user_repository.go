package memory

import (
	"errors"
	"sync"

	"github.com/rabbicse/auth-service/internal/domain/aggregates/user"
	"github.com/rabbicse/auth-service/internal/shared"
)

type UserRepository struct {
	mu           sync.RWMutex
	usersByID    map[string]*user.User
	usersByUN    map[string]*user.User
	usersByEmail map[string]*user.User
}

func NewUserRepository(seed []*user.User) *UserRepository {

	repo := &UserRepository{
		usersByID:    make(map[string]*user.User),
		usersByUN:    make(map[string]*user.User),
		usersByEmail: make(map[string]*user.User),
	}

	for _, u := range seed {
		repo.usersByID[u.ID] = u
		repo.usersByUN[u.Username] = u
		repo.usersByEmail[u.Email] = u
	}

	return repo
}

func (r *UserRepository) FindByID(id string) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.usersByID[id]
	if !ok {
		return nil, shared.ErrUserNotFound
	}

	return u, nil
}

func (r *UserRepository) FindByEmail(email string) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.usersByEmail[email]
	if !ok {
		return nil, shared.ErrUserNotFound
	}

	return u, nil
}

func (r *UserRepository) Save(u *user.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.usersByEmail[u.Email]; exists {
		return errors.New("email already registered")
	}

	r.usersByID[u.ID] = u
	r.usersByUN[u.Username] = u
	r.usersByEmail[u.Email] = u

	return nil
}

func (r *UserRepository) FindByUsername(username string) (*user.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	u, ok := r.usersByUN[username]
	if !ok {
		return nil, shared.ErrUserNotFound
	}

	return u, nil
}
