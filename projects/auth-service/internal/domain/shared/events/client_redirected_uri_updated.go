package events

import "time"

type ClientRedirectURIsUpdated struct {
	ClientID     string
	RedirectURIs []string
	Time         time.Time
}

func (e ClientRedirectURIsUpdated) Name() string {
	return "ClientRedirectURIsUpdated"
}

func (e ClientRedirectURIsUpdated) OccurredAt() time.Time {
	if e.Time.IsZero() {
		return time.Now()
	}
	return e.Time
}
