package theater

import "errors"

var (
	ErrTheaterNotFound = errors.New("theater not found")
	ErrScreenNotFound  = errors.New("screen not found")
)
