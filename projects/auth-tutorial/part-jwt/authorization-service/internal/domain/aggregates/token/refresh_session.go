package token

import "time"

type RefreshSession struct {
	Token     string
	UserID    string
	ClientID  string
	ExpiresAt time.Time
}
