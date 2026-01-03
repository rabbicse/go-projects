package authorization

import (
	"oauth-ddd/internal/domain/valueobjects"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/shared"
)

// AuthorizationFactory creates and reconstitutes Authorization aggregates
type AuthorizationFactory struct{}

func NewAuthorizationFactory() *AuthorizationFactory {
	return &AuthorizationFactory{}
}

// Reconstitute recreates an Authorization aggregate from persistence
func (f *AuthorizationFactory) Reconstitute(
	code string,
	clientID string,
	userID string,
	redirectURI string,
	scopes []string,
	expiresAt time.Time,
	used bool,
	createdAt time.Time,
) (*Authorization, error) {

	authCode, err := valueobjects.NewAuthorizationCode(code)
	if err != nil {
		return nil, err
	}

	cid, err := valueobjects.NewClientID(clientID)
	if err != nil {
		return nil, err
	}

	uid, err := valueobjects.NewUserID(userID)
	if err != nil {
		return nil, err
	}

	redirect, err := valueobjects.NewRedirectURI(redirectURI)
	if err != nil {
		return nil, err
	}

	var scopeObjs []valueobjects.Scope
	for _, scope := range scopes {
		s, err := valueobjects.NewScope(scope)
		if err != nil {
			return nil, err
		}
		scopeObjs = append(scopeObjs, s)
	}

	return &Authorization{
		code:        authCode,
		clientID:    cid,
		userID:      uid,
		redirectURI: redirect,
		scopes:      scopeObjs,
		expiresAt:   expiresAt,
		used:        used,
		CreatedAt:   createdAt,
		events:      []shared.DomainEvent{},
	}, nil
}
