package login

import "time"

type Token struct {
	Value     string
	UserID    string
	ExpiresAt time.Time
	Used      bool
}

func (t *Token) IsExpired(now time.Time) bool {
	return now.After(t.ExpiresAt)
}
