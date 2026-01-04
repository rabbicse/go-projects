package events

import "time"

// TokenRevoked event - ADD THIS
type TokenRevoked struct {
	AccessToken string
	ClientID    string
	UserID      string
	RevokedAt   time.Time
	Time        time.Time
}

func (e TokenRevoked) Name() string {
	return "TokenRevoked"
}

func (e TokenRevoked) OccurredAt() time.Time {
	if e.Time.IsZero() {
		return time.Now()
	}
	return e.Time
}
