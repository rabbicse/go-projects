package authorization

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/shared"
	"github.com/rabbicse/auth-service/internal/domain/shared/events"
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

// NewAuthorization creates a new Authorization aggregate
func NewAuthorization(
	clientID string,
	userID string,
	redirectURI string,
	scopes []string,
) (*Authorization, error) {

	// Validate and create value objects
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
		scopeObjs = append(scopeObjs, *s)
	}

	// Generate authorization code
	code, err := generateSecureCode()
	if err != nil {
		return nil, err
	}

	authCode, err := valueobjects.NewAuthorizationCode(code)
	if err != nil {
		return nil, err
	}

	auth := &Authorization{
		code:        *authCode,
		clientID:    *cid,
		userID:      uid,
		redirectURI: *redirect,
		scopes:      scopeObjs,
		expiresAt:   time.Now().Add(10 * time.Minute), // RFC 6749: short-lived
		used:        false,
		CreatedAt:   time.Now(),
		events:      []shared.DomainEvent{},
	}

	auth.AddEvent(events.AuthorizationCreated{
		Code:        auth.code.Value(),
		ClientID:    auth.clientID.Value(),
		UserID:      auth.userID.Value(),
		RedirectURI: auth.redirectURI.Value(),
		Scopes:      scopes,
		ExpiresAt:   auth.expiresAt,
	})

	return auth, nil
}

// Getters
func (a *Authorization) Code() valueobjects.AuthorizationCode {
	return a.code
}

func (a *Authorization) ClientID() valueobjects.ClientID {
	return a.clientID
}

func (a *Authorization) UserID() valueobjects.UserID {
	return a.userID
}

func (a *Authorization) RedirectURI() valueobjects.RedirectURI {
	return a.redirectURI
}

func (a *Authorization) Scopes() []string {
	var scopes []string
	for _, scope := range a.scopes {
		scopes = append(scopes, scope.Value())
	}
	return scopes
}

func (a *Authorization) IsUsed() bool {
	return a.used
}

func (a *Authorization) ExpiresAt() time.Time {
	return a.expiresAt
}

// Domain Methods
func (a *Authorization) Validate() error {
	if a.used {
		return errors.New("authorization code already used")
	}

	if time.Now().After(a.expiresAt) {
		return errors.New("authorization code expired")
	}

	return nil
}

func (a *Authorization) MarkAsUsed() error {
	if err := a.Validate(); err != nil {
		return err
	}

	a.used = true

	a.AddEvent(events.AuthorizationUsed{
		Code:     a.code.Value(),
		ClientID: a.clientID.Value(),
		UserID:   a.userID.Value(),
	})

	return nil
}

func (a *Authorization) VerifyClient(clientID string) error {
	cid, err := valueobjects.NewClientID(clientID)
	if err != nil {
		return err
	}

	if !a.clientID.Equals(*cid) {
		return errors.New("authorization code issued to different client")
	}

	return nil
}

func (a *Authorization) VerifyRedirectURI(redirectURI string) error {
	uri, err := valueobjects.NewRedirectURI(redirectURI)
	if err != nil {
		return err
	}

	if !a.redirectURI.Equals(*uri) {
		return errors.New("redirect URI mismatch")
	}

	return nil
}

func (a *Authorization) AddEvent(event shared.DomainEvent) {
	a.events = append(a.events, event)
}

func (a *Authorization) ClearEvents() {
	a.events = []shared.DomainEvent{}
}

func (a *Authorization) GetEvents() []shared.DomainEvent {
	return a.events
}

// Helper function
func generateSecureCode() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
