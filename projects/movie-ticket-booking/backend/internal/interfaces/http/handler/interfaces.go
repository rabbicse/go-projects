package handler

import (
	"context"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
)

// BookingService is the booking use-case contract that BookingHandler depends on.
// Defined here so tests can substitute a mock without importing the concrete service.
type BookingService interface {
	HoldSeats(ctx context.Context, userID, showtimeID string, seatIDs []string) (booking.Session, error)
	ConfirmBooking(ctx context.Context, sessionID, userID string) (booking.Booking, error)
	ReleaseBooking(ctx context.Context, sessionID, userID string) error
	GetSeatMap(ctx context.Context, showtimeID, requestingUserID string) ([]booking.SeatStatus, error)
	GetUserBookings(ctx context.Context, userID string) ([]booking.Booking, error)
}

// MovieService is the movie use-case contract that MovieHandler and AdminHandler depend on.
type MovieService interface {
	ListMovies(ctx context.Context) ([]movie.Movie, error)
	GetMovie(ctx context.Context, id string) (movie.Movie, error)
	GetShowtime(ctx context.Context, showtimeID string) (movie.Showtime, error)
	CreateMovie(ctx context.Context, m movie.Movie) error
	CreateShowtime(ctx context.Context, st movie.Showtime) error
}
