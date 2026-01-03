package valueobjects

import "errors"

type ClientID struct {
	ID string
}

func NewClientID(value string) (*ClientID, error) {
	if value == "" {
		return &ClientID{}, errors.New("client ID cannot be empty")
	}

	if len(value) > 100 {
		return &ClientID{}, errors.New("client ID too long")
	}

	return &ClientID{ID: value}, nil
}

func (c ClientID) Value() string {
	return c.ID
}

func (c ClientID) Equals(other ClientID) bool {
	return c.ID == other.ID
}
