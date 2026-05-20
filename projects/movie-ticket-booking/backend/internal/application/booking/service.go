package booking

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
)

type Service struct {
	seatLock    booking.SeatLockRepository
	bookingRepo booking.Repository
	movieRepo   movie.Repository
	maxSeats    int
	holdTTL     time.Duration
}

func NewService(
	seatLock booking.SeatLockRepository,
	bookingRepo booking.Repository,
	movieRepo movie.Repository,
	maxSeats int,
	holdTTL time.Duration,
) *Service {
	return &Service{
		seatLock:    seatLock,
		bookingRepo: bookingRepo,
		movieRepo:   movieRepo,
		maxSeats:    maxSeats,
		holdTTL:     holdTTL,
	}
}

// HoldSeats locks up to maxSeats seats for the requesting user.
func (s *Service) HoldSeats(ctx context.Context, userID, showtimeID string, seatIDs []string) (booking.Session, error) {
	if len(seatIDs) == 0 {
		return booking.Session{}, booking.ErrNoSeatsSelected
	}
	if len(seatIDs) > s.maxSeats {
		return booking.Session{}, fmt.Errorf("%w: max %d", booking.ErrMaxSeatsExceeded, s.maxSeats)
	}

	for _, id := range seatIDs {
		if _, err := booking.NewSeat(id); err != nil {
			return booking.Session{}, fmt.Errorf("invalid seat %q: %w", id, err)
		}
	}

	showtime, err := s.movieRepo.FindShowtime(ctx, showtimeID)
	if err != nil {
		return booking.Session{}, fmt.Errorf("showtime %s not found: %w", showtimeID, err)
	}

	sessionID := uuid.New().String()
	req := booking.HoldRequest{
		SessionID:  sessionID,
		UserID:     userID,
		ShowtimeID: showtimeID,
		MovieID:    showtime.MovieID,
		SeatIDs:    seatIDs,
		HoldTTL:    int(s.holdTTL.Seconds()),
	}

	session, err := s.seatLock.HoldSeats(ctx, req)
	if err != nil {
		return booking.Session{}, err
	}

	seats := make([]booking.Seat, len(seatIDs))
	for i, id := range seatIDs {
		seats[i], _ = booking.NewSeat(id)
	}

	b, err := booking.New(sessionID, userID, showtimeID, showtime.MovieID, seats, showtime.Price, s.holdTTL)
	if err != nil {
		return booking.Session{}, err
	}
	b.ID = uuid.New().String()

	if saveErr := s.bookingRepo.Save(ctx, b); saveErr != nil {
		slog.Warn("failed to persist held booking", "error", saveErr, "session_id", sessionID)
	}

	return session, nil
}

// ConfirmBooking finalises the hold: removes TTLs in Redis and marks MongoDB record confirmed.
func (s *Service) ConfirmBooking(ctx context.Context, sessionID, userID string) (booking.Booking, error) {
	session, err := s.seatLock.GetSession(ctx, sessionID)
	if err != nil {
		return booking.Booking{}, booking.ErrSessionNotFound
	}
	if session.UserID != userID {
		return booking.Booking{}, booking.ErrUnauthorized
	}

	b, err := s.bookingRepo.FindBySessionID(ctx, sessionID)
	if err != nil {
		return booking.Booking{}, fmt.Errorf("booking record not found: %w", err)
	}
	if err := b.Confirm(); err != nil {
		return booking.Booking{}, err
	}

	if err := s.seatLock.ConfirmSession(ctx, sessionID); err != nil {
		return booking.Booking{}, fmt.Errorf("confirm redis session: %w", err)
	}
	if err := s.bookingRepo.Update(ctx, b); err != nil {
		slog.Warn("failed to update booking status in mongodb", "error", err, "session_id", sessionID)
	}

	return b, nil
}

// ReleaseBooking cancels a held booking, freeing all seats.
func (s *Service) ReleaseBooking(ctx context.Context, sessionID, userID string) error {
	session, err := s.seatLock.GetSession(ctx, sessionID)
	if err != nil {
		return booking.ErrSessionNotFound
	}
	if session.UserID != userID {
		return booking.ErrUnauthorized
	}

	if err := s.seatLock.ReleaseSession(ctx, sessionID); err != nil {
		return fmt.Errorf("release redis session: %w", err)
	}

	b, err := s.bookingRepo.FindBySessionID(ctx, sessionID)
	if err == nil {
		_ = b.Release()
		if updateErr := s.bookingRepo.Update(ctx, b); updateErr != nil {
			slog.Warn("failed to mark booking as released in mongodb", "error", updateErr)
		}
	}

	return nil
}

// GetSeatMap returns real-time seat availability for a showtime.
// HeldByMe is set correctly for the requesting userID.
func (s *Service) GetSeatMap(ctx context.Context, showtimeID, userID string) ([]booking.SeatStatus, error) {
	statuses, err := s.seatLock.GetSeatStatuses(ctx, showtimeID, userID)
	if err != nil {
		return nil, fmt.Errorf("get seat statuses: %w", err)
	}
	return statuses, nil
}

// GetUserBookings returns all bookings for a user from MongoDB.
func (s *Service) GetUserBookings(ctx context.Context, userID string) ([]booking.Booking, error) {
	bookings, err := s.bookingRepo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user bookings: %w", err)
	}
	return bookings, nil
}

// pricePerSeat exposes the helper for the handler layer.
func (s *Service) ShowtimePrice(ctx context.Context, showtimeID string) (shared.Money, error) {
	st, err := s.movieRepo.FindShowtime(ctx, showtimeID)
	if err != nil {
		return shared.Money{}, err
	}
	return st.Price, nil
}
