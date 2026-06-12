package apierr_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/payment"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
)

// TestHTTPStatusFor verifies:
//  1. Correct HTTP status and machine-readable code for every known domain error.
//  2. No call-chain prefixes appear in the message (B-04: no infrastructure leakage).
//
// Wrapped errors simulate the real application path where e.g. BookingService wraps
// a domain sentinel before returning it up the call stack.
func TestHTTPStatusFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            error
		wantStatus     int
		wantCode       string
		mustNotContain string // presence would indicate a call-chain leak
	}{
		{
			name:           "seat already held — direct",
			err:            booking.ErrSeatAlreadyHeld,
			wantStatus:     http.StatusConflict,
			wantCode:       "SEATS_UNAVAILABLE",
		},
		{
			name:           "seat already held — wrapped (simulates infra layer)",
			err:            fmt.Errorf("hold seats lua: %w", booking.ErrSeatAlreadyHeld),
			wantStatus:     http.StatusConflict,
			wantCode:       "SEATS_UNAVAILABLE",
			mustNotContain: "lua",
		},
		{
			name:       "session not found",
			err:        booking.ErrSessionNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   "SESSION_NOT_FOUND",
		},
		{
			name:       "session expired",
			err:        booking.ErrSessionExpired,
			wantStatus: http.StatusGone,
			wantCode:   "SESSION_EXPIRED",
		},
		{
			name:           "invalid status transition — wrapped (B-04 regression)",
			err:            fmt.Errorf("release redis session: %w", booking.ErrInvalidStatusTransition),
			wantStatus:     http.StatusConflict,
			wantCode:       "INVALID_STATUS_TRANSITION",
			mustNotContain: "redis session",
		},
		{
			name:       "unauthorized",
			err:        booking.ErrUnauthorized,
			wantStatus: http.StatusForbidden,
			wantCode:   "UNAUTHORIZED",
		},
		{
			name:       "max seats exceeded",
			err:        booking.ErrMaxSeatsExceeded,
			wantStatus: http.StatusBadRequest,
			wantCode:   "MAX_SEATS_EXCEEDED",
		},
		{
			name:       "no seats selected",
			err:        booking.ErrNoSeatsSelected,
			wantStatus: http.StatusBadRequest,
			wantCode:   "NO_SEATS_SELECTED",
		},
		{
			name:       "booking not found",
			err:        booking.ErrBookingNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   "BOOKING_NOT_FOUND",
		},
		{
			name:       "payment declined",
			err:        payment.ErrPaymentDeclined,
			wantStatus: http.StatusPaymentRequired,
			wantCode:   "PAYMENT_DECLINED",
		},
		{
			name:       "movie not found",
			err:        movie.ErrMovieNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   "MOVIE_NOT_FOUND",
		},
		{
			name:       "showtime not found",
			err:        movie.ErrShowtimeNotFound,
			wantStatus: http.StatusNotFound,
			wantCode:   "SHOWTIME_NOT_FOUND",
		},
		{
			name:           "unknown error — internal detail must not leak",
			err:            errors.New("mongodb: write conflict on collection bookings at line 42"),
			wantStatus:     http.StatusInternalServerError,
			wantCode:       "INTERNAL_ERROR",
			mustNotContain: "mongodb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			status, resp := apierr.HTTPStatusFor(tt.err)

			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}
			if resp.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", resp.Code, tt.wantCode)
			}
			if tt.mustNotContain != "" && strings.Contains(resp.Message, tt.mustNotContain) {
				t.Errorf("message %q must not contain %q (call-chain leak detected)", resp.Message, tt.mustNotContain)
			}
		})
	}
}

// TestFormatBindError verifies user-facing messages for bind error types.
func TestFormatBindError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		err          error
		wantContains string
	}{
		{
			name:         "empty body (io.EOF)",
			err:          io.EOF,
			wantContains: "empty",
		},
		{
			name:         "truncated body (ErrUnexpectedEOF)",
			err:          io.ErrUnexpectedEOF,
			wantContains: "empty",
		},
		{
			name:         "malformed JSON",
			err:          &json.SyntaxError{},
			wantContains: "malformed JSON",
		},
		{
			name:         "wrong value type",
			err:          &json.UnmarshalTypeError{Field: "amount_cents"},
			wantContains: "amount_cents",
		},
		{
			name:         "unknown error falls back to generic message",
			err:          errors.New("some internal detail that must not be exposed"),
			wantContains: "invalid request body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg := apierr.FormatBindError(tt.err)
			if !strings.Contains(msg, tt.wantContains) {
				t.Errorf("FormatBindError = %q, want substring %q", msg, tt.wantContains)
			}
		})
	}
}
