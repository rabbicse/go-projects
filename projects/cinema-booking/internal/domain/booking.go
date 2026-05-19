package domain

// Booking represents a confirmed seat reservation.
type Booking struct {
	ID      string
	MovieID string
	SeatID  string
	UserID  string
	Status  string
}

type BookingStore interface {
	Book(booking Booking) (Booking, error)
	ListBookings(movieID string) []Booking
}
