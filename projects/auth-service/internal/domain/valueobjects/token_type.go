package valueobjects

import "errors"

// TokenType represents the type of token
type TokenType struct {
	Value string
}

func NewTokenType(value string) (TokenType, error) {
	if value == "" {
		return TokenType{}, errors.New("token type cannot be empty")
	}

	// Only Bearer tokens supported for now (RFC 6750)
	if value != "Bearer" {
		return TokenType{}, errors.New("only Bearer token type is supported")
	}

	return TokenType{Value: value}, nil
}

func (t TokenType) Equals(other TokenType) bool {
	return t.Value == other.Value
}
