package services

import (
	"context"

	"github.com/rabbicse/cinema-booking/internal/domain"
)

type Service struct {
	store domain.BookingStore
}

func NewService(store domain.BookingStore) *Service {
	return &Service{store}
}

func (s *Service) Book(b domain.Booking) (domain.Booking, error) {
	return s.store.Book(b)
}

func (s *Service) ListBookings(movieID string) []domain.Booking {
	return s.store.ListBookings(movieID)
}

func (s *Service) ConfirmSeat(ctx context.Context, sessionID string, userID string) (domain.Booking, error) {
	return s.store.Confirm(ctx, sessionID, userID)
}

func (s *Service) ReleaseSeat(ctx context.Context, sessionID string, userID string) error {
	return s.store.Release(ctx, sessionID, userID)
}
