package login

import "time"

type AuthLevel string

const (
	AuthPassword    AuthLevel = "PASSWORD"
	AuthMFAVerified AuthLevel = "MFA_VERIFIED"
)

type Token struct {
	Value     string
	UserID    string
	ExpiresAt time.Time
	Used      bool
	AuthLevel AuthLevel
}

func (t *Token) IsExpired(now time.Time) bool {
	return now.After(t.ExpiresAt)
}
