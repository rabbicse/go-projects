package jwt

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rabbicse/auth-service/internal/application/oidc"
)

type RSASigner struct {
	key *rsa.PrivateKey
}

func NewRSASigner(key *rsa.PrivateKey) *RSASigner {
	return &RSASigner{key: key}
}

func (s *RSASigner) Sign(claims oidc.IDTokenClaims) (string, error) {
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
