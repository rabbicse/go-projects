package token

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/shared"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
)

type Token struct {
	// Token fields would be defined here
	// Token is the Aggregate Root for Token bounded context
	accessToken  valueobjects.AccessToken
	refreshToken *valueobjects.RefreshToken
	tokenType    valueobjects.TokenType
	expiresIn    valueobjects.TokenExpiry
	scopes       []valueobjects.Scope
	clientID     valueobjects.ClientID
	userID       valueobjects.UserID
	issuedAt     time.Time
	revokedAt    *time.Time

	events []shared.DomainEvent
}

// NewToken creates a new Token aggregate
func NewToken(
	clientID string,
	userID string,
	scopes []string,
	tokenType valueobjects.TokenType,
	expiresIn time.Duration,
	includeRefreshToken bool,
) (*Token, error) {

	// Validate and create value objects
	cid, err := valueobjects.NewClientID(clientID)
	if err != nil {
		return nil, err
	}

	uid, err := valueobjects.NewUserID(userID)
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

	expiry, err := valueobjects.NewTokenExpiry(int(expiresIn.Seconds()))
	if err != nil {
		return nil, err
	}

	// Generate tokens
	accessToken, err := generateSecureToken()
	if err != nil {
		return nil, err
	}

	accessTokenVO, err := valueobjects.NewAccessToken(accessToken)
	if err != nil {
		return nil, err
	}

	token := &Token{
		accessToken: accessTokenVO,
		tokenType:   tokenType,
		expiresIn:   expiry,
		scopes:      scopeObjs,
		clientID:    cid,
		userID:      uid,
		issuedAt:    time.Now(),
		events:      []DomainEvent{},
	}

	// Generate refresh token if requested
	if includeRefreshToken {
		refreshToken, err := generateSecureToken()
		if err != nil {
			return nil, err
		}

		refreshTokenVO, err := valueobjects.NewRefreshToken(refreshToken)
		if err != nil {
			return nil, err
		}

		refreshExpiry, err := valueobjects.NewTokenExpiry(int((24 * 7 * time.Hour).Seconds()))
		if err != nil {
			return nil, err
		}

		token.refreshToken = &refreshTokenVO
		token.expiresIn = refreshExpiry
	}

	token.AddEvent(TokenIssued{
		TokenType:    token.tokenType.Value(),
		AccessToken:  token.accessToken.Value(),
		RefreshToken: token.RefreshTokenValue(),
		ClientID:     token.clientID.Value(),
		UserID:       token.userID.Value(),
		Scopes:       token.ScopesString(),
		ExpiresIn:    token.expiresIn.Value(),
	})

	return token, nil
}

// Getters
func (t *Token) AccessToken() valueobjects.AccessToken {
	return t.accessToken
}

func (t *Token) RefreshToken() *valueobjects.RefreshToken {
	return t.refreshToken
}

func (t *Token) RefreshTokenValue() string {
	if t.refreshToken == nil {
		return ""
	}
	return t.refreshToken.Value()
}

func (t *Token) TokenType() valueobjects.TokenType {
	return t.tokenType
}

func (t *Token) ExpiresIn() valueobjects.TokenExpiry {
	return t.expiresIn
}

func (t *Token) ClientID() valueobjects.ClientID {
	return t.clientID
}

func (t *Token) UserID() valueobjects.UserID {
	return t.userID
}

func (t *Token) ScopesString() []string {
	var scopes []string
	for _, scope := range t.scopes {
		scopes = append(scopes, scope.Value())
	}
	return scopes
}

func (t *Token) IssuedAt() time.Time {
	return t.issuedAt
}

func (t *Token) IsRevoked() bool {
	return t.revokedAt != nil
}

// Domain Methods
func (t *Token) Validate() error {
	if t.IsRevoked() {
		return errors.New("token has been revoked")
	}

	if t.IsExpired() {
		return errors.New("token has expired")
	}

	return nil
}

func (t *Token) IsExpired() bool {
	expiryTime := t.issuedAt.Add(time.Duration(t.expiresIn.Value()) * time.Second)
	return time.Now().After(expiryTime)
}

func (t *Token) Revoke() {
	now := time.Now()
	t.revokedAt = &now

	t.AddEvent(TokenRevoked{
		AccessToken: t.accessToken.Value(),
		ClientID:    t.clientID.Value(),
		UserID:      t.userID.Value(),
		RevokedAt:   now,
	})
}

func (t *Token) Refresh(newScopes []string) (*Token, error) {
	if t.refreshToken == nil {
		return nil, errors.New("no refresh token available")
	}

	if err := t.Validate(); err != nil {
		return nil, err
	}

	// Revoke the old token
	t.Revoke()

	// Use requested scopes or original scopes if none specified
	scopesToUse := t.ScopesString()
	if len(newScopes) > 0 {
		// Validate new scopes are subset of original scopes
		for _, newScope := range newScopes {
			valid := false
			for _, originalScope := range scopesToUse {
				if newScope == originalScope {
					valid = true
					break
				}
			}
			if !valid {
				return nil, errors.New("requested scope not originally granted")
			}
		}
		scopesToUse = newScopes
	}

	// Issue new token
	newToken, err := NewToken(
		t.clientID.Value(),
		t.userID.Value(),
		scopesToUse,
		t.tokenType,
		time.Duration(t.expiresIn.Value())*time.Second,
		true,
	)
	if err != nil {
		return nil, err
	}

	t.AddEvent(TokenRefreshed{
		OldAccessToken: t.accessToken.Value(),
		NewAccessToken: newToken.accessToken.Value(),
		ClientID:       t.clientID.Value(),
		UserID:         t.userID.Value(),
	})

	return newToken, nil
}

func (t *Token) AddEvent(event shared.DomainEvent) {
	t.events = append(t.events, event)
}

func (t *Token) ClearEvents() {
	t.events = []shared.DomainEvent{}
}

func (t *Token) GetEvents() []shared.DomainEvent {
	return t.events
}

// Helper function
func generateSecureToken() (string, error) {
	bytes := make([]byte, 64)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
