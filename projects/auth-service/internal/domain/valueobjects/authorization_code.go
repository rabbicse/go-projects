package valueobjects

import (
	"errors"
	"regexp"
)

type AuthorizationCode struct {
	Code string
}

func NewAuthorizationCode(value string) (*AuthorizationCode, error) {
	if value == "" {
		return &AuthorizationCode{}, errors.New("authorization code cannot be empty")
	}

	// RFC 6749: Authorization codes should be reasonably short
	if len(value) < 16 || len(value) > 256 {
		return &AuthorizationCode{}, errors.New("invalid authorization code length")
	}

	// Basic format validation
	if !regexp.MustCompile(`^[a-zA-Z0-9\-._~+/]+$`).MatchString(value) {
		return &AuthorizationCode{}, errors.New("invalid authorization code format")
	}

	return &AuthorizationCode{Code: value}, nil
}

func (a AuthorizationCode) Value() string {
	return a.Code
}

func (a AuthorizationCode) Equals(other AuthorizationCode) bool {
	return a.Code == other.Code
}
