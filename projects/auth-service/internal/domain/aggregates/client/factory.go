package client

import (
	"oauth-ddd/internal/domain/valueobjects"
	"time"
)

// ClientFactory creates and validates Client aggregates
type ClientFactory struct{}

func NewClientFactory() *ClientFactory {
	return &ClientFactory{}
}

// CreateConfidentialClient creates a confidential client with secret
func (f *ClientFactory) CreateConfidentialClient(id, name, secret string, redirectURIs, scopes []string) (*Client, error) {
	client, err := NewClient(id, name, ClientTypeConfidential)
	if err != nil {
		return nil, err
	}

	if err := client.SetSecret(secret); err != nil {
		return nil, err
	}

	if err := client.UpdateRedirectURIs(redirectURIs); err != nil {
		return nil, err
	}

	if err := client.UpdateAllowedScopes(scopes); err != nil {
		return nil, err
	}

	return client, nil
}

// CreatePublicClient creates a public client (no secret)
func (f *ClientFactory) CreatePublicClient(id, name string, redirectURIs, scopes []string) (*Client, error) {
	client, err := NewClient(id, name, ClientTypePublic)
	if err != nil {
		return nil, err
	}

	if err := client.UpdateRedirectURIs(redirectURIs); err != nil {
		return nil, err
	}

	if err := client.UpdateAllowedScopes(scopes); err != nil {
		return nil, err
	}

	return client, nil
}

// Reconstitute recreates a Client aggregate from persistence
func (f *ClientFactory) Reconstitute(
	id string,
	name string,
	secretHash string,
	redirectURIs []string,
	allowedScopes []string,
	clientType ClientType,
	active bool,
	createdAt time.Time,
	updatedAt time.Time,
) (*Client, error) {

	clientID, err := valueobjects.NewClientID(id)
	if err != nil {
		return nil, err
	}

	client := &Client{
		ID:         clientID,
		Name:       name,
		SecretHash: secretHash,
		Type:       clientType,
		Active:     active,
		createdAt:  createdAt,
		updatedAt:  updatedAt,
		Events:     []DomainEvent{},
	}

	// Reconstitute redirect URIs
	var uris []valueobjects.RedirectURI
	for _, uri := range redirectURIs {
		redirectURI, err := valueobjects.NewRedirectURI(uri)
		if err != nil {
			return nil, err
		}
		uris = append(uris, redirectURI)
	}
	client.RedirectURIs = uris

	// Reconstitute allowed scopes
	var scopes []valueobjects.Scope
	for _, scope := range allowedScopes {
		s, err := valueobjects.NewScope(scope)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, s)
	}
	client.AllowedScopes = scopes

	return client, nil
}
