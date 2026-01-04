package events

import "time"

// AuthorizationUsed event - emitted when authorization code is exchanged for tokens
type AuthorizationUsed struct {
	Code     string
	ClientID string
	UserID   string
	Time     time.Time
}

func (e AuthorizationUsed) Name() string {
	return "AuthorizationUsed"
}

func (e AuthorizationUsed) OccurredAt() time.Time {
	if e.Time.IsZero() {
		return time.Now()
	}
	return e.Time
}
