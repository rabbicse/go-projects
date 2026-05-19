package services

import (
	"sync"

	"github.com/rabbicse/cinema-booking/internal/domain"
)

type ConcurrentStore struct {
	bookings map[string]domain.Booking
	sync.RWMutex
}

func NewConcurrentStore() *ConcurrentStore {
	return &ConcurrentStore{
		bookings: map[string]domain.Booking{},
	}
}

func (store *ConcurrentStore) Book(booking domain.Booking) error {
	store.Lock()
	defer store.Unlock()

	// if seat is already booked, return error
	if _, exists := store.bookings[booking.SeatID]; exists {
		return domain.ErrSeatAlreadyBooked
	}
	store.bookings[booking.SeatID] = booking
	return nil
}

func (store *ConcurrentStore) ListBookings(movieID string) []domain.Booking {
	store.RLock()
	defer store.RUnlock()

	var bookings []domain.Booking
	for _, booking := range store.bookings {
		if booking.MovieID == movieID {
			bookings = append(bookings, booking)
		}
	}
	return bookings
}
