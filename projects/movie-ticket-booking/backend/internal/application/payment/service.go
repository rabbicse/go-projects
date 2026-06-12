package payment

import (
	"context"
	"time"

	"github.com/google/uuid"
	bookingsvc "github.com/rabbicse/movie-ticket-booking/internal/application/booking"
	bookingdomain "github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/payment"
)

// Gateway is the interface for a payment provider.
type Gateway interface {
	Charge(amountCents int64, currency string, card payment.CardDetails) (transactionID string, err error)
}

// PayResult holds the payment record and the confirmed booking on success.
type PayResult struct {
	Payment payment.Payment
	Booking bookingdomain.Booking
}

// Service orchestrates payment processing and booking confirmation.
type Service struct {
	gateway    Gateway
	bookingSvc *bookingsvc.Service
}

func NewService(gateway Gateway, bookingSvc *bookingsvc.Service) *Service {
	return &Service{gateway: gateway, bookingSvc: bookingSvc}
}

func (s *Service) Pay(
	ctx context.Context,
	sessionID, userID string,
	amountCents int64,
	currency string,
	card payment.CardDetails,
) (PayResult, error) {
	p := payment.Payment{
		ID:          uuid.New().String(),
		SessionID:   sessionID,
		UserID:      userID,
		AmountCents: amountCents,
		Currency:    currency,
		Status:      payment.StatusPending,
		CreatedAt:   time.Now(),
	}

	_, err := s.gateway.Charge(amountCents, currency, card)
	if err != nil {
		p.Status = payment.StatusFailed
		p.FailReason = err.Error()
		return PayResult{Payment: p}, payment.ErrPaymentDeclined
	}

	b, err := s.bookingSvc.ConfirmBooking(ctx, sessionID, userID)
	if err != nil {
		p.Status = payment.StatusFailed
		p.FailReason = "booking confirmation failed after payment"
		return PayResult{Payment: p}, err
	}

	p.Status = payment.StatusCompleted
	return PayResult{Payment: p, Booking: b}, nil
}
