package shared

import "time"

type ClientType string

const (
	ClientTypeConfidential ClientType = "confidential"
	ClientTypePublic       ClientType = "public"
)

// Domain Events
type DomainEvent interface {
	Name() string
	OccurredAt() time.Time
}

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
