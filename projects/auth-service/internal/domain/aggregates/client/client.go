package client

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/shared"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
)

type Client struct {
	ID            valueobjects.ClientID
	Name          string
	Type          shared.ClientType
	RedirectURIs  []valueobjects.RedirectURI
	AllowedScopes []valueobjects.Scope
	SecretHash    string
	Active        bool
	createdAt     time.Time
	updatedAt     time.Time

	// Domain events that this aggregate raises
	events []shared.DomainEvent
}
