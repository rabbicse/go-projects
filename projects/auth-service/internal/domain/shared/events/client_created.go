package events

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/shared"
)

type ClientCreated struct {
	ClientID   string
	ClientName string
	Type       shared.ClientType
	Time       time.Time
}

func (e ClientCreated) Name() string {
	return "ClientCreated"
}

func (e ClientCreated) OccurredAt() time.Time {
	if e.Time.IsZero() {
		return time.Now()
	}
	return e.Time
}
