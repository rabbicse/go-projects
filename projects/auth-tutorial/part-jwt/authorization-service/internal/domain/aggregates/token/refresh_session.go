package token

import "time"

type RefreshSession struct {
	Token     string
	UserID    string
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
}
