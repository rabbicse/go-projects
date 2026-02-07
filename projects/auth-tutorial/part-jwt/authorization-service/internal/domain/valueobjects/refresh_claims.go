package valueobjects

import "github.com/golang-jwt/jwt/v5"

type RefreshClaims struct {
	Sub string `json:"sub"`
	Jti string `json:"jti,omitempty"`
	jwt.RegisteredClaims
}
