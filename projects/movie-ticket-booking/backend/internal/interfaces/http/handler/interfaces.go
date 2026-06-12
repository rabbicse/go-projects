package handler

import (
	"context"

	authapp "github.com/rabbicse/movie-ticket-booking/internal/application/auth"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/show"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/theater"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
)

// AuthService is the auth use-case contract for AuthHandler.
// Defined here so tests can substitute a mock without importing the concrete service.
type AuthService interface {
	Register(ctx context.Context, in authapp.RegisterInput) (*user.User, *authapp.TokenPair, error)
	Login(ctx context.Context, email, password string) (*authapp.TokenPair, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*authapp.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	GetProfile(ctx context.Context, userID string) (*user.User, error)
}

// BookingService is the booking use-case contract that BookingHandler depends on.
// Defined here so tests can substitute a mock without importing the concrete service.
type BookingService interface {
	HoldSeats(ctx context.Context, userID, showtimeID string, seatIDs []string) (booking.Session, error)
	ConfirmBooking(ctx context.Context, sessionID, userID string) (booking.Booking, error)
	ReleaseBooking(ctx context.Context, sessionID, userID string) error
	GetSeatMap(ctx context.Context, showtimeID, requestingUserID string) ([]booking.SeatStatus, error)
	GetUserBookings(ctx context.Context, userID string) ([]booking.Booking, error)
}

// MovieService is the movie use-case contract that MovieHandler depends on.
type MovieService interface {
	ListMovies(ctx context.Context) ([]movie.Movie, error)
	GetMovie(ctx context.Context, id string) (movie.Movie, error)
	GetShowtime(ctx context.Context, showtimeID string) (movie.Showtime, error)
	CreateMovie(ctx context.Context, m movie.Movie) error
	CreateShowtime(ctx context.Context, st movie.Showtime) error
}

// AdminMovieService extends MovieService with mutation operations for the admin panel.
type AdminMovieService interface {
	MovieService
	UpdateMovie(ctx context.Context, m movie.Movie) error
	DeleteMovie(ctx context.Context, id string) error
	DeleteShowtime(ctx context.Context, showtimeID string) error
	PublishMovie(ctx context.Context, id string) (movie.Movie, error)
	UnpublishMovie(ctx context.Context, id string) (movie.Movie, error)
}

// BookingEnricher provides movie/showtime metadata for enriching booking history responses.
// Satisfied by MovieService — both methods are already part of that interface.
type BookingEnricher interface {
	GetShowtime(ctx context.Context, showtimeID string) (movie.Showtime, error)
	GetMovie(ctx context.Context, id string) (movie.Movie, error)
}

// AdminBookingService provides aggregate booking stats for the admin dashboard.
type AdminBookingService interface {
	GetStats(ctx context.Context) (booking.BookingStats, error)
}

// TheaterService is the theater/screen use-case contract for TheaterHandler.
type TheaterService interface {
	ListTheaters(ctx context.Context) ([]theater.Theater, error)
	GetTheater(ctx context.Context, id string) (theater.Theater, error)
	CreateTheater(ctx context.Context, t theater.Theater) error
	UpdateTheater(ctx context.Context, t theater.Theater) error
	DisableTheater(ctx context.Context, id string) (theater.Theater, error)
	ListScreens(ctx context.Context, theaterID string) ([]theater.Screen, error)
	GetScreen(ctx context.Context, id string) (theater.Screen, error)
	CreateScreen(ctx context.Context, sc theater.Screen) error
	UpdateScreen(ctx context.Context, sc theater.Screen) error
	DisableScreen(ctx context.Context, id string) (theater.Screen, error)
}

// ShowService is the show scheduling use-case contract for ShowHandler.
type ShowService interface {
	ListShows(ctx context.Context) ([]show.Show, error)
	GetShow(ctx context.Context, id string) (show.Show, error)
	CreateShow(ctx context.Context, s show.Show) error
	UpdateShow(ctx context.Context, s show.Show) error
	CancelShow(ctx context.Context, id string) (show.Show, error)
}
