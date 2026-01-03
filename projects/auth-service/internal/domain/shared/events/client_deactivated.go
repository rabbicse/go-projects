package events

import "time"

type ClientDeactivated struct {
	ClientID string
	Time     time.Time
}

func (e ClientDeactivated) Name() string {
	return "ClientDeactivated"
}

func (e ClientDeactivated) OccurredAt() time.Time {
	if e.Time.IsZero() {
		return time.Now()
	}
	return e.Time
}
