package valueobjects

import "errors"

// TokenExpiry represents token expiry in seconds
type TokenExpiry struct {
	Value int
}

func NewTokenExpiry(value int) (*TokenExpiry, error) {
	if value <= 0 {
		return &TokenExpiry{}, errors.New("token expiry must be positive")
	}

	// Reasonable limits
	if value > 365*24*60*60 { // 1 year
		return &TokenExpiry{}, errors.New("token expiry too long")
	}

	return &TokenExpiry{Value: value}, nil
}

func (t TokenExpiry) Equals(other TokenExpiry) bool {
	return t.Value == other.Value
}
