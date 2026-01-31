package authentication

import "time"

type LoginChallenge struct {
	ID        string
	UserID    string
	Value     []byte
	ExpiresAt time.Time
	Used      bool
}

func (c *LoginChallenge) IsExpired(now time.Time) bool {
	return now.After(c.ExpiresAt)
}
