package valueobjects

import "github.com/golang-jwt/jwt/v5"

type AccessClaims struct {
	UserID   string         `json:"sub,omitempty"`
	ClientID string         `json:"client_id,omitempty"`
	Scope    string         `json:"scope,omitempty"` // space separated
	Roles    []string       `json:"roles,omitempty"`
	Extra    map[string]any `json:"-"` // or use private fields + custom Marshal
	jwt.RegisteredClaims
}
