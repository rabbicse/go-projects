package valueobjects

import "github.com/golang-jwt/jwt/v5"

type IDClaims struct {
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`

	jwt.RegisteredClaims
}
