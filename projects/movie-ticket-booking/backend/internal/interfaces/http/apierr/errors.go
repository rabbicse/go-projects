package apierr

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/payment"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/show"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/theater"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
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
//
// Canonical messages are used for all known errors (not err.Error()) to prevent
// infrastructure call-chain prefixes from leaking through the API boundary.
// Unknown errors always return 500 with a generic message.
func HTTPStatusFor(err error) (int, ErrorResponse) {
	var ve *movie.ValidationError
	if errors.As(err, &ve) {
		return http.StatusUnprocessableEntity, New("VALIDATION_ERROR", ve.Error())
	}
	var tve *theater.ValidationError
	if errors.As(err, &tve) {
		return http.StatusUnprocessableEntity, New("VALIDATION_ERROR", tve.Error())
	}
	var sve *show.ValidationError
	if errors.As(err, &sve) {
		return http.StatusUnprocessableEntity, New("VALIDATION_ERROR", sve.Error())
	}

	switch {
	// booking domain
	case errors.Is(err, booking.ErrSeatAlreadyHeld):
		return http.StatusConflict, New("SEATS_UNAVAILABLE", "one or more selected seats are no longer available")
	case errors.Is(err, booking.ErrSessionNotFound):
		return http.StatusNotFound, New("SESSION_NOT_FOUND", "session not found or already expired")
	case errors.Is(err, booking.ErrSessionExpired):
		return http.StatusGone, New("SESSION_EXPIRED", "your hold has expired; please select seats again")
	case errors.Is(err, booking.ErrUnauthorized):
		return http.StatusForbidden, New("UNAUTHORIZED", "this session belongs to a different user")
	case errors.Is(err, booking.ErrInvalidStatusTransition):
		return http.StatusConflict, New("INVALID_STATUS_TRANSITION", "this booking cannot be modified in its current state")
	case errors.Is(err, booking.ErrMaxSeatsExceeded):
		return http.StatusBadRequest, New("MAX_SEATS_EXCEEDED", "maximum seats per booking exceeded")
	case errors.Is(err, booking.ErrNoSeatsSelected):
		return http.StatusBadRequest, New("NO_SEATS_SELECTED", "at least one seat must be selected")
	case errors.Is(err, booking.ErrBookingNotFound):
		return http.StatusNotFound, New("BOOKING_NOT_FOUND", "booking not found")
	// payment domain
	case errors.Is(err, payment.ErrPaymentDeclined):
		return http.StatusPaymentRequired, New("PAYMENT_DECLINED", "card payment declined; please try a different card")
	// catalog domain
	case errors.Is(err, movie.ErrMovieNotFound):
		return http.StatusNotFound, New("MOVIE_NOT_FOUND", "movie not found")
	case errors.Is(err, movie.ErrShowtimeNotFound):
		return http.StatusNotFound, New("SHOWTIME_NOT_FOUND", "showtime not found")
	// theater domain
	case errors.Is(err, theater.ErrTheaterNotFound):
		return http.StatusNotFound, New("THEATER_NOT_FOUND", "theater not found")
	case errors.Is(err, theater.ErrScreenNotFound):
		return http.StatusNotFound, New("SCREEN_NOT_FOUND", "screen not found")
	// show domain
	case errors.Is(err, show.ErrShowNotFound):
		return http.StatusNotFound, New("SHOW_NOT_FOUND", "show not found")
	case errors.Is(err, show.ErrShowConflict):
		return http.StatusConflict, New("SHOW_CONFLICT", "show time conflicts with an existing show on this screen")
	case errors.Is(err, show.ErrShowCancelled):
		return http.StatusConflict, New("SHOW_CANCELLED", "show is already cancelled")
	// user / auth domain
	case errors.Is(err, user.ErrEmailTaken):
		return http.StatusConflict, New("EMAIL_TAKEN", "this email address is already registered")
	case errors.Is(err, user.ErrInvalidPassword):
		return http.StatusUnauthorized, New("INVALID_CREDENTIALS", "invalid email or password")
	case errors.Is(err, user.ErrUserNotFound):
		return http.StatusNotFound, New("USER_NOT_FOUND", "user not found")
	case errors.Is(err, user.ErrTokenInvalid):
		return http.StatusUnauthorized, New("TOKEN_INVALID", "authentication token is invalid or expired")
	default:
		return http.StatusInternalServerError, New("INTERNAL_ERROR", "an unexpected error occurred")
	}
}

// FormatBindError converts a ShouldBindJSON error into a user-facing message.
//
// It handles the three error classes gin binding can produce:
//   - validator.ValidationErrors  — field-level constraint violations
//   - *json.SyntaxError           — malformed JSON body
//   - *json.UnmarshalTypeError    — wrong value type for a field
//   - io.EOF / ErrUnexpectedEOF   — empty or truncated body
func FormatBindError(err error) string {
	var ve validator.ValidationErrors
	if errors.As(err, &ve) {
		msgs := make([]string, 0, len(ve))
		for _, fe := range ve {
			msgs = append(msgs, fieldMsg(fe))
		}
		return strings.Join(msgs, "; ")
	}

	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		return "request body contains malformed JSON"
	}

	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		return fmt.Sprintf("field %q must be a %s", typeErr.Field, typeErr.Type)
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "request body is empty or incomplete"
	}

	return "invalid request body"
}

// fieldMsg converts a single validator.FieldError to a user-readable sentence.
func fieldMsg(fe validator.FieldError) string {
	field := toSnakeCase(fe.Field())
	switch fe.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "min":
		return fmt.Sprintf("%s must contain at least %s item(s)", field, fe.Param())
	case "max":
		return fmt.Sprintf("%s must contain at most %s item(s)", field, fe.Param())
	case "gt":
		return fmt.Sprintf("%s must be greater than %s", field, fe.Param())
	case "gte":
		return fmt.Sprintf("%s must be at least %s", field, fe.Param())
	case "lte":
		return fmt.Sprintf("%s must be at most %s", field, fe.Param())
	case "len":
		return fmt.Sprintf("%s must be exactly %s character(s)", field, fe.Param())
	case "email":
		return fmt.Sprintf("%s must be a valid email address", field)
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, strings.ReplaceAll(fe.Param(), " ", ", "))
	default:
		return fmt.Sprintf("%s is invalid", field)
	}
}

// reFirstCap and reAllCap convert PascalCase/camelCase field names to snake_case
// so that error messages refer to fields by their JSON name (e.g. SeatIDs → seat_ids).
var (
	reFirstCap = regexp.MustCompile(`(.)([A-Z][a-z]+)`)
	reAllCap   = regexp.MustCompile(`([a-z0-9])([A-Z])`)
)

func toSnakeCase(s string) string {
	s = reFirstCap.ReplaceAllString(s, `${1}_${2}`)
	s = reAllCap.ReplaceAllString(s, `${1}_${2}`)
	return strings.ToLower(s)
}
