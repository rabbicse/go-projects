package events

import "time"

// AuthorizationCreated event - emitted when authorization code is created
type AuthorizationCreated struct {
	Code        string
	ClientID    string
	UserID      string
	RedirectURI string
	Scopes      []string
	ExpiresAt   time.Time
	Time        time.Time
}

func (e AuthorizationCreated) Name() string {
	return "AuthorizationCreated"
}

func (e AuthorizationCreated) OccurredAt() time.Time {
	if e.Time.IsZero() {
		return time.Now()
	}
	return e.Time
}
