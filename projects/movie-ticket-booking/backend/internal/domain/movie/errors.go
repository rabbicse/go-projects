package movie

import "errors"

var (
	ErrMovieNotFound    = errors.New("movie not found")
	ErrShowtimeNotFound = errors.New("showtime not found")
)
