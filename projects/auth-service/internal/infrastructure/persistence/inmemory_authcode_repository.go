package persistence

import (
	"sync"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/aggregates/authorization"
	"github.com/rabbicse/auth-service/internal/domain/repositories"
)

type InMemoryAuthCodeRepository struct {
	codes   map[string]*authorization.Authorization
	mu      sync.RWMutex
	factory *authorization.AuthorizationFactory
}

func NewInMemoryAuthCodeRepository(factory *authorization.AuthorizationFactory) repositories.AuthorizationRepository {
	return &InMemoryAuthCodeRepository{
		codes:   make(map[string]*authorization.Authorization),
		factory: factory,
	}
}

func (r *InMemoryAuthCodeRepository) FindByCode(code string) (*authorization.Authorization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	auth, exists := r.codes[code]
	if !exists {
		return nil, &AuthorizationNotFoundError{Code: code}
	}

	return auth, nil
}

func (r *InMemoryAuthCodeRepository) Save(auth *authorization.Authorization) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.codes[auth.Code().Value()] = auth
	auth.ClearEvents()
	return nil
}

func (r *InMemoryAuthCodeRepository) Delete(code string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.codes, code)
	return nil
}

func (r *InMemoryAuthCodeRepository) FindByClientID(clientID string, from, to time.Time) ([]*authorization.Authorization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*authorization.Authorization
	for _, auth := range r.codes {
		if auth.ClientID().Value() == clientID &&
			!auth.CreatedAt.Before(from) &&
			!auth.CreatedAt.After(to) {
			result = append(result, auth)
		}
	}

	return result, nil
}

func (r *InMemoryAuthCodeRepository) FindByUserID(userID string, from, to time.Time) ([]*authorization.Authorization, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*authorization.Authorization
	for _, auth := range r.codes {
		if auth.UserID().Value() == userID &&
			!auth.CreatedAt.Before(from) &&
			!auth.CreatedAt.After(to) {
			result = append(result, auth)
		}
	}

	return result, nil
}

func (r *InMemoryAuthCodeRepository) DeleteExpired(before time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for code, auth := range r.codes {
		if auth.ExpiresAt().Before(before) {
			delete(r.codes, code)
		}
	}

	return nil
}

type AuthorizationNotFoundError struct {
	Code string
}

func (e AuthorizationNotFoundError) Error() string {
	return "authorization not found: " + e.Code
}
