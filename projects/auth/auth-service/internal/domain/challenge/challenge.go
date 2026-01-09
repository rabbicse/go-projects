package challenge

import "time"

type Challenge struct {
	ID        string
	UserID    string
	Value     []byte
	ExpiresAt time.Time
	Used      bool
}

func (c *Challenge) IsExpired(now time.Time) bool {
	return now.After(c.ExpiresAt)
}
