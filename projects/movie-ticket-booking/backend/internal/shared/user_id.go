package shared

import (
	"errors"
	"strings"
)

// UserID is a value object representing a user's identifier.
type UserID struct {
	value string
}

var ErrEmptyUserID = errors.New("user ID must not be empty")

func NewUserID(v string) (UserID, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return UserID{}, ErrEmptyUserID
	}
	return UserID{value: v}, nil
}

func (id UserID) String() string { return id.value }
func (id UserID) IsZero() bool   { return id.value == "" }
