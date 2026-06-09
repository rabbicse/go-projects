package events

import (
	"context"
	"log/slog"

	sharedkernel "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

// Handler processes a single domain event.
type Handler func(ctx context.Context, event sharedkernel.DomainEvent) error

// Dispatcher routes domain events to registered handlers.
type Dispatcher interface {
	Register(eventName string, handler Handler)
	Dispatch(ctx context.Context, events []sharedkernel.DomainEvent)
}

// InProcess is a synchronous, in-process event dispatcher.
// All handlers run in the caller's goroutine before the use-case returns.
// Swap for a message broker (e.g. NATS JetStream) to get async/durable delivery.
type InProcess struct {
	handlers map[string][]Handler
}

func NewInProcess() *InProcess {
	return &InProcess{handlers: make(map[string][]Handler)}
}

func (d *InProcess) Register(eventName string, h Handler) {
	d.handlers[eventName] = append(d.handlers[eventName], h)
}

func (d *InProcess) Dispatch(ctx context.Context, events []sharedkernel.DomainEvent) {
	for _, evt := range events {
		for _, h := range d.handlers[evt.EventName()] {
			if err := h(ctx, evt); err != nil {
				slog.Error("event handler failed",
					"event", evt.EventName(),
					"error", err)
			}
		}
	}
}

// LogHandler returns a Handler that logs every domain event at INFO level.
func LogHandler() Handler {
	return func(ctx context.Context, evt sharedkernel.DomainEvent) error {
		slog.Info("domain event",
			"event", evt.EventName(),
			"occurred_at", evt.OccurredAt())
		return nil
	}
}
