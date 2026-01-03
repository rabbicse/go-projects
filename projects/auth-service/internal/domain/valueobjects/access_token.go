package valueobjects

import "errors"

// AccessToken represents an OAuth 2.0 access token
type AccessToken struct {
	Value string
}

func NewAccessToken(value string) (*AccessToken, error) {
	if value == "" {
		return &AccessToken{}, errors.New("access token cannot be empty")
	}

	// RFC 6750: Bearer tokens should be opaque strings
	if len(value) < 32 {
		return &AccessToken{}, errors.New("access token too short")
	}

	return &AccessToken{Value: value}, nil
}

func (a AccessToken) Equals(other AccessToken) bool {
	return a.Value == other.Value
}
