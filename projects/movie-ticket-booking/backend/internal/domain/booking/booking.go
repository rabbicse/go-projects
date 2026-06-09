package booking

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
	sharedkernel "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

// Status represents the lifecycle of a booking.
type Status string

const (
	StatusHeld      Status = "held"
	StatusConfirmed Status = "confirmed"
	StatusReleased  Status = "released"
	StatusExpired   Status = "expired"
)

// Booking is the aggregate root for the booking bounded context.
// It is persisted in MongoDB for history and analytics.
type Booking struct {
	ID          string
	SessionID   string
	UserID      string
	ShowtimeID  string
	MovieID     string
	Seats       []Seat
	Status      Status
	TotalPrice  shared.Money
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ExpiresAt   time.Time
	ConfirmedAt *time.Time
	events      []sharedkernel.DomainEvent
}

// newID generates a UUID v4 using only stdlib — no external deps in the domain.
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func New(sessionID, userID, showtimeID, movieID string, seats []Seat, pricePerSeat shared.Money, holdTTL time.Duration) (Booking, error) {
	if len(seats) == 0 {
		return Booking{}, ErrNoSeatsSelected
	}
	now := time.Now().UTC()
	id := newID()
	b := Booking{
		ID:         id,
		SessionID:  sessionID,
		UserID:     userID,
		ShowtimeID: showtimeID,
		MovieID:    movieID,
		Seats:      seats,
		Status:     StatusHeld,
		TotalPrice: pricePerSeat.Multiply(len(seats)),
		CreatedAt:  now,
		UpdatedAt:  now,
		ExpiresAt:  now.Add(holdTTL),
	}
	b.events = append(b.events, BookingCreated{
		EventBase:  sharedkernel.NewEventBase(EventNameBookingCreated),
		BookingID:  id,
		SessionID:  sessionID,
		UserID:     userID,
		ShowtimeID: showtimeID,
		TotalCents: b.TotalPrice.Cents(),
	})
	return b, nil
}

func (b *Booking) Confirm() error {
	if b.Status != StatusHeld {
		return ErrInvalidStatusTransition
	}
	if time.Now().UTC().After(b.ExpiresAt) {
		return ErrSessionExpired
	}
	now := time.Now().UTC()
	b.Status = StatusConfirmed
	b.UpdatedAt = now
	b.ConfirmedAt = &now
	b.events = append(b.events, BookingConfirmed{
		EventBase:  sharedkernel.NewEventBase(EventNameBookingConfirmed),
		BookingID:  b.ID,
		SessionID:  b.SessionID,
		UserID:     b.UserID,
		TotalCents: b.TotalPrice.Cents(),
	})
	return nil
}

func (b *Booking) Release() error {
	if b.Status != StatusHeld {
		return ErrInvalidStatusTransition
	}
	b.Status = StatusReleased
	b.UpdatedAt = time.Now().UTC()
	b.events = append(b.events, BookingReleased{
		EventBase: sharedkernel.NewEventBase(EventNameBookingReleased),
		BookingID: b.ID,
		SessionID: b.SessionID,
		UserID:    b.UserID,
	})
	return nil
}

// Expire transitions a held booking to expired when the hold TTL fires.
func (b *Booking) Expire() error {
	if b.Status != StatusHeld {
		return ErrInvalidStatusTransition
	}
	b.Status = StatusExpired
	b.UpdatedAt = time.Now().UTC()
	b.events = append(b.events, BookingExpired{
		EventBase: sharedkernel.NewEventBase(EventNameBookingExpired),
		BookingID: b.ID,
		SessionID: b.SessionID,
		UserID:    b.UserID,
	})
	return nil
}

// PopEvents returns all accumulated domain events and clears the internal slice.
func (b *Booking) PopEvents() []sharedkernel.DomainEvent {
	evts := b.events
	b.events = nil
	return evts
}

func (b *Booking) SeatIDs() []string {
	ids := make([]string, len(b.Seats))
	for i, s := range b.Seats {
		ids[i] = s.ID
	}
	return ids
}
