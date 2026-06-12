package show

import "errors"

var (
	ErrShowNotFound  = errors.New("show not found")
	ErrShowConflict  = errors.New("show time conflicts with an existing show on this screen")
	ErrShowCancelled = errors.New("show is already cancelled")
)

// ValidationError carries a human-readable validation message for show inputs.
type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }
