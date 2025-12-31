package authorization

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/shared"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
)

// Authorization is the Aggregate Root for Authorization bounded context
type Authorization struct {
	// Define fields for the Authorization aggregate
	code        valueobjects.AuthorizationCode
	clientID    valueobjects.ClientID
	userID      valueobjects.UserID
	redirectURI valueobjects.RedirectURI
	scopes      []valueobjects.Scope
	expiresAt   time.Time
	used        bool
	CreatedAt   time.Time
	updatedAt   time.Time

	// Domain events that this aggregate raises
	events []shared.DomainEvent
}
