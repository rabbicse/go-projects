package valueobjects

import "errors"

type UserID struct {
	value string
}

func NewUserID(value string) (UserID, error) {
	if value == "" {
		return UserID{}, errors.New("user ID cannot be empty")
	}

	return UserID{value: value}, nil
}

func (u UserID) Value() string {
	return u.value
}

func (u UserID) Equals(other UserID) bool {
	return u.value == other.value
}
