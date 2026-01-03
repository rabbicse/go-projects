package valueobjects

import "errors"

// RefreshToken represents an OAuth 2.0 refresh token
type RefreshToken struct {
	Value string
}

func NewRefreshToken(value string) (RefreshToken, error) {
	if value == "" {
		return RefreshToken{}, errors.New("refresh token cannot be empty")
	}

	// Refresh tokens should be even more secure
	if len(value) < 64 {
		return RefreshToken{}, errors.New("refresh token too short")
	}

	return RefreshToken{Value: value}, nil
}

func (r RefreshToken) Equals(other RefreshToken) bool {
	return r.Value == other.Value
}
