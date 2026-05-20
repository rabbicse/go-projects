package booking

import "errors"

var (
	ErrSeatAlreadyHeld         = errors.New("one or more seats are already held or confirmed")
	ErrSessionNotFound         = errors.New("session not found or expired")
	ErrSessionExpired          = errors.New("hold session has expired")
	ErrUnauthorized            = errors.New("session does not belong to this user")
	ErrInvalidStatusTransition = errors.New("invalid booking status transition")
	ErrNoSeatsSelected         = errors.New("at least one seat must be selected")
	ErrMaxSeatsExceeded        = errors.New("number of seats exceeds maximum allowed per session")
	ErrBookingNotFound         = errors.New("booking not found")
)
