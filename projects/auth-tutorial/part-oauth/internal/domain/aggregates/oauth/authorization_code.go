package oauth

import "time"

type AuthorizationCode struct {
	Code        string
	ClientID    string
	UserID      string
	RedirectURI string
	Scopes      []string
	ExpiresAt   time.Time
}

func (a *AuthorizationCode) IsExpired(now time.Time) bool {
	return now.After(a.ExpiresAt)
}
