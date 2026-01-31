package token

import "time"

type Token struct {
	AccessToken  string
	RefreshToken string
	IDToken      string

	ClientID string
	UserID   string
	Scopes   []string

	ExpiresAt time.Time
}

func (t *Token) IsExpired(now time.Time) bool {
	return now.After(t.ExpiresAt)
}
