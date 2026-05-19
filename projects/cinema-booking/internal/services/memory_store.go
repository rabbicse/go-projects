package services

import (
	"github.com/rabbicse/cinema-booking/internal/domain"
)

type MemoryStore struct {
	bookings map[string]domain.Booking
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		bookings: map[string]domain.Booking{},
	}
}

func (store *MemoryStore) Book(booking domain.Booking) error {
	// if seat is already booked, return error
	if _, exists := store.bookings[booking.SeatID]; exists {
		return domain.ErrSeatAlreadyBooked
	}
	store.bookings[booking.SeatID] = booking
	return nil
}

func (store *MemoryStore) ListBookings(movieID string) []domain.Booking {
	var bookings []domain.Booking
	for _, booking := range store.bookings {
		if booking.MovieID == movieID {
			bookings = append(bookings, booking)
		}
	}
	return bookings
}
