package jwt

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

type JwtTokenGenerator struct {
	key *rsa.PrivateKey
}

func NewJwtTokenGenerator(key *rsa.PrivateKey) *JwtTokenGenerator {
	return &JwtTokenGenerator{key: key}
}

func (s *JwtTokenGenerator) Sign(claims oidc.IDTokenClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   claims.Issuer,
		"sub":   claims.Subject,
		"aud":   claims.Audience,
		"iat":   claims.IssuedAt,
		"exp":   claims.ExpiresAt,
		"email": claims.Email,
	})

	return token.SignedString(s.key)
}
