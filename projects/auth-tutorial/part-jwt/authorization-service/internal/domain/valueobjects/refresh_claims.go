package valueobjects

import "github.com/golang-jwt/jwt/v5"

type RefreshClaims struct {
	UserID string `json:"sub,omitempty"`
	jwt.RegisteredClaims
}
