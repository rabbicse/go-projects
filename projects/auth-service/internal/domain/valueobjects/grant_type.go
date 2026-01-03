package valueobjects

import "errors"

// GrantType represents OAuth 2.0 grant type
type GrantType struct {
	Value string
}

func NewGrantType(value string) (*GrantType, error) {
	validTypes := map[string]bool{
		"authorization_code": true,
		"implicit":           true,
		"password":           true,
		"client_credentials": true,
		"refresh_token":      true,
	}

	if !validTypes[value] {
		return &GrantType{}, errors.New("invalid grant type")
	}

	return &GrantType{Value: value}, nil
}

func (g GrantType) Equals(other GrantType) bool {
	return g.Value == other.Value
}
