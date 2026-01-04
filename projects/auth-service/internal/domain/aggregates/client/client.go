package client

import (
	"errors"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/shared"
	"github.com/rabbicse/auth-service/internal/domain/shared/events"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
	"golang.org/x/crypto/bcrypt"
)

type Client struct {
	ID            valueobjects.ClientID
	Name          string
	Type          shared.ClientType
	RedirectURIs  []valueobjects.RedirectURI
	AllowedScopes []valueobjects.Scope
	SecretHash    string
	Active        bool
	CreatedAt     time.Time
	UpdatedAt     time.Time

	// Domain events that this aggregate raises
	Events []shared.DomainEvent
}

// NewClient creates a new Client aggregate
func NewClient(id, name string, clientType shared.ClientType) (*Client, error) {
	clientID, err := valueobjects.NewClientID(id)
	if err != nil {
		return nil, err
	}

	if name == "" {
		return nil, errors.New("client name cannot be empty")
	}

	client := &Client{
		ID:        *clientID,
		Name:      name,
		Type:      clientType,
		Active:    true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Events:    []shared.DomainEvent{},
	}

	client.AddEvent(events.ClientCreated{
		ClientID:   client.ID.ID,
		ClientName: client.Name,
		Type:       client.Type,
	})

	return client, nil
}

// Domain Methods
func (c *Client) UpdateRedirectURIs(uris []string) error {
	var redirectURIs []valueobjects.RedirectURI
	for _, uri := range uris {
		redirectURI, err := valueobjects.NewRedirectURI(uri)
		if err != nil {
			return err
		}
		redirectURIs = append(redirectURIs, *redirectURI)
	}

	c.RedirectURIs = redirectURIs
	c.UpdatedAt = time.Now()

	c.AddEvent(events.ClientRedirectURIsUpdated{
		ClientID:     c.ID.ID,
		RedirectURIs: uris,
	})

	return nil
}

func (c *Client) UpdateAllowedScopes(scopes []string) error {
	var allowedScopes []valueobjects.Scope
	for _, scope := range scopes {
		s, err := valueobjects.NewScope(scope)
		if err != nil {
			return err
		}
		allowedScopes = append(allowedScopes, *s)
	}

	c.AllowedScopes = allowedScopes
	c.UpdatedAt = time.Now()

	return nil
}

func (c *Client) SetSecret(secret string) error {
	if c.Type == shared.ClientTypePublic {
		return errors.New("public clients cannot have secrets")
	}

	if secret == "" {
		return errors.New("client secret cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	c.SecretHash = string(hash)
	c.UpdatedAt = time.Now()

	return nil
}

func (c *Client) Authenticate(secret string) error {
	if c.Type == shared.ClientTypePublic {
		// Public clients don't require authentication
		return nil
	}

	if c.SecretHash == "" {
		return errors.New("client has no secret configured")
	}

	err := bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(secret))
	if err != nil {
		return errors.New("invalid client credentials")
	}

	return nil
}

func (c *Client) ValidateRedirectURI(redirectURI string) error {
	uri, err := valueobjects.NewRedirectURI(redirectURI)
	if err != nil {
		return err
	}

	for _, allowed := range c.RedirectURIs {
		if allowed.Equals(*uri) {
			return nil
		}
	}

	return errors.New("redirect URI not allowed for this client")
}

func (c *Client) ValidateScopes(requestedScopes []string) error {
	for _, requested := range requestedScopes {
		scope, err := valueobjects.NewScope(requested)
		if err != nil {
			return err
		}

		allowed := false
		for _, allowedScope := range c.AllowedScopes {
			if allowedScope.Equals(*scope) {
				allowed = true
				break
			}
		}

		if !allowed {
			return errors.New("scope not allowed: " + requested)
		}
	}

	return nil
}

func (c *Client) Deactivate() {
	c.Active = false
	c.UpdatedAt = time.Now()

	c.AddEvent(events.ClientDeactivated{
		ClientID: c.ID.Value(),
	})
}

func (c *Client) AddEvent(event shared.DomainEvent) {
	c.Events = append(c.Events, event)
}

func (c *Client) ClearEvents() {
	c.Events = []shared.DomainEvent{}
}

func (c *Client) GetEvents() []shared.DomainEvent {
	return c.Events
}
