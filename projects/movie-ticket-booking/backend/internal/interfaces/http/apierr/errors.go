package apierr

import (
	"errors"
	"net/http"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
)

// ErrorResponse is the canonical error envelope returned by every API endpoint.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// New creates an ErrorResponse with a machine-readable code and human-readable message.
func New(code, message string) ErrorResponse {
	return ErrorResponse{Code: code, Message: message}
}

// HTTPStatusFor maps a domain error to an HTTP status code and ErrorResponse.
// Unknown errors always return 500 with a generic message (prevents internal detail leakage).
func HTTPStatusFor(err error) (int, ErrorResponse) {
	switch {
	// booking domain
	case errors.Is(err, booking.ErrSeatAlreadyHeld):
		return http.StatusConflict, New("SEATS_UNAVAILABLE", err.Error())
	case errors.Is(err, booking.ErrSessionNotFound):
		return http.StatusNotFound, New("SESSION_NOT_FOUND", err.Error())
	case errors.Is(err, booking.ErrSessionExpired):
		return http.StatusGone, New("SESSION_EXPIRED", err.Error())
	case errors.Is(err, booking.ErrUnauthorized):
		return http.StatusForbidden, New("UNAUTHORIZED", err.Error())
	case errors.Is(err, booking.ErrInvalidStatusTransition):
		return http.StatusConflict, New("INVALID_STATUS_TRANSITION", err.Error())
	case errors.Is(err, booking.ErrMaxSeatsExceeded):
		return http.StatusBadRequest, New("MAX_SEATS_EXCEEDED", err.Error())
	case errors.Is(err, booking.ErrNoSeatsSelected):
		return http.StatusBadRequest, New("NO_SEATS_SELECTED", err.Error())
	case errors.Is(err, booking.ErrBookingNotFound):
		return http.StatusNotFound, New("BOOKING_NOT_FOUND", err.Error())
	// catalog domain
	case errors.Is(err, movie.ErrMovieNotFound):
		return http.StatusNotFound, New("MOVIE_NOT_FOUND", err.Error())
	case errors.Is(err, movie.ErrShowtimeNotFound):
		return http.StatusNotFound, New("SHOWTIME_NOT_FOUND", err.Error())
	default:
		return http.StatusInternalServerError, New("INTERNAL_ERROR", "an unexpected error occurred")
	}
}
