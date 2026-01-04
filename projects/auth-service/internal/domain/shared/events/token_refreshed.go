package events

import "time"

// TokenRefreshed event
type TokenRefreshed struct {
	OldAccessToken string
	NewAccessToken string
	ClientID       string
	UserID         string
	Time           time.Time
}

func (e TokenRefreshed) Name() string {
	return "TokenRefreshed"
}

func (e TokenRefreshed) OccurredAt() time.Time {
	if e.Time.IsZero() {
		return time.Now()
	}
	return e.Time
}
