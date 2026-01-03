package valueobjects

import (
	"errors"
	"net/url"
)

type RedirectURI struct {
	URI string
}

// func NewRedirectURI(uri string) *RedirectURI {
// 	return &RedirectURI{
// 		URI: uri,
// 	}
// }

func NewRedirectURI(value string) (*RedirectURI, error) {
	if value == "" {
		return &RedirectURI{}, errors.New("redirect URI cannot be empty")
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return &RedirectURI{}, errors.New("invalid redirect URI format")
	}

	// RFC 6749: Must be absolute URI
	if !parsed.IsAbs() {
		return &RedirectURI{}, errors.New("redirect URI must be absolute")
	}

	// Disallow fragments (RFC 6749 Section 3.1.2)
	if parsed.Fragment != "" {
		return &RedirectURI{}, errors.New("redirect URI must not contain fragment")
	}

	return &RedirectURI{URI: value}, nil
}

func (r RedirectURI) Value() string {
	return r.URI
}

func (r RedirectURI) Equals(other RedirectURI) bool {
	return r.URI == other.URI
}
