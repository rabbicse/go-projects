package repositories

import (
	"github.com/rabbicse/auth-service/internal/domain/aggregates/client"
	"github.com/rabbicse/auth-service/pkg/errors"
)

// ClientRepository defines the interface for Client aggregate persistence
type ClientRepository interface {
	// FindByID retrieves a client by its ID
	FindByID(id string) (*client.Client, error)

	// FindByName retrieves a client by its name
	FindByName(name string) (*client.Client, error)

	// Save persists a client aggregate
	Save(client *client.Client) error

	// Delete removes a client
	Delete(id string) error

	// List returns all clients (with pagination)
	List(offset, limit int) ([]*client.Client, error)

	// Exists checks if a client with given ID exists
	Exists(id string) (bool, error)
}

// ClientNotFoundError is returned when a client is not found
type ClientNotFoundError struct {
	ClientID string
}

func (e ClientNotFoundError) Error() string {
	return "client not found: " + e.ClientID
}

func (e ClientNotFoundError) DomainError() *errors.DomainError {
	return errors.NewDomainError("invalid_client", "Client not found: %s", e.ClientID)
}
