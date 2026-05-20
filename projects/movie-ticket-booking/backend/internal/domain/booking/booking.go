package booking

import (
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
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
}

func New(sessionID, userID, showtimeID, movieID string, seats []Seat, pricePerSeat shared.Money, holdTTL time.Duration) (Booking, error) {
	if len(seats) == 0 {
		return Booking{}, ErrNoSeatsSelected
	}
	now := time.Now().UTC()
	return Booking{
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
	}, nil
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
	return nil
}

func (b *Booking) Release() error {
	if b.Status != StatusHeld {
		return ErrInvalidStatusTransition
	}
	b.Status = StatusReleased
	b.UpdatedAt = time.Now().UTC()
	return nil
}

func (b *Booking) SeatIDs() []string {
	ids := make([]string, len(b.Seats))
	for i, s := range b.Seats {
		ids[i] = s.ID
	}
	return ids
}
