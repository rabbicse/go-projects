package application

import (
	"github.com/rabbicse/cinema-booking/internal/domain"
)

type BookingService struct {
	store domain.BookingStore
}

func NewBookingService(store domain.BookingStore) *BookingService {
	return &BookingService{store}
}
