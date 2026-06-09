package shared

import "time"

// DomainEvent is the base interface for all domain events.
type DomainEvent interface {
	EventName() string
	OccurredAt() time.Time
}

// EventBase provides common fields for domain events.
type EventBase struct {
	name       string
	occurredAt time.Time
}

func NewEventBase(name string) EventBase {
	return EventBase{name: name, occurredAt: time.Now()}
}

func (e EventBase) EventName() string     { return e.name }
func (e EventBase) OccurredAt() time.Time { return e.occurredAt }
