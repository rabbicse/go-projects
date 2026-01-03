package repositories

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/aggregates/authorization"
)

// AuthorizationRepository defines the interface for Authorization aggregate persistence
type AuthorizationRepository interface {
	// FindByCode retrieves an authorization by its code
	FindByCode(code string) (*authorization.Authorization, error)

	// Save persists an authorization aggregate
	Save(auth *authorization.Authorization) error

	// Delete removes an authorization
	Delete(code string) error

	// FindByClientID finds authorizations for a specific client
	FindByClientID(clientID string, from, to time.Time) ([]*authorization.Authorization, error)

	// FindByUserID finds authorizations for a specific user
	FindByUserID(userID string, from, to time.Time) ([]*authorization.Authorization, error)

	// DeleteExpired removes expired authorizations
	DeleteExpired(before time.Time) error
}
