package movie

import (
	"errors"
	"strings"
)

var (
	ErrMovieNotFound    = errors.New("movie not found")
	ErrShowtimeNotFound = errors.New("showtime not found")
)

// ValidationError holds one or more invariant violations from a Movie domain method.
type ValidationError struct {
	Messages []string
}

func (e *ValidationError) Error() string {
	return strings.Join(e.Messages, "; ")
}
