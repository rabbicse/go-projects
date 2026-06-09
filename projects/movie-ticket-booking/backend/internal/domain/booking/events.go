package booking

import sharedkernel "github.com/rabbicse/movie-ticket-booking/internal/shared"

const (
	EventNameBookingCreated   = "booking.created"
	EventNameBookingConfirmed = "booking.confirmed"
	EventNameBookingReleased  = "booking.released"
	EventNameBookingExpired   = "booking.expired"
)

type BookingCreated struct {
	sharedkernel.EventBase
	BookingID  string
	SessionID  string
	UserID     string
	ShowtimeID string
	TotalCents int64
}

type BookingConfirmed struct {
	sharedkernel.EventBase
	BookingID  string
	SessionID  string
	UserID     string
	TotalCents int64
}

type BookingReleased struct {
	sharedkernel.EventBase
	BookingID string
	SessionID string
	UserID    string
}

type BookingExpired struct {
	sharedkernel.EventBase
	BookingID string
	SessionID string
	UserID    string
}
