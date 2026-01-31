package authentication

import "time"

type LoginToken struct {
	Value     string
	UserID    string
	ExpiresAt time.Time
	Used      bool
}

func (t *LoginToken) IsExpired(now time.Time) bool {
	return now.After(t.ExpiresAt)
}
