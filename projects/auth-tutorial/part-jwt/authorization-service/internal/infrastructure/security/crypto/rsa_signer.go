package crypto

import (
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

type RSASigner struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
}

func NewRSASigner(
	priv *rsa.PrivateKey,
	pub *rsa.PublicKey,
	kid string,
) *RSASigner {
	return &RSASigner{
		privateKey: priv,
		publicKey:  pub,
		kid:        kid,
	}
}

func (s *RSASigner) Sign(claims any) (string, error) {

	token := jwt.NewWithClaims(
		jwt.SigningMethodRS256,
		claims.(jwt.Claims),
	)

	token.Header["kid"] = s.kid

	return token.SignedString(s.privateKey)
}

func (s *RSASigner) PublicKey() *rsa.PublicKey {
	return s.publicKey
}

func (s *RSASigner) Kid() string {
	return s.kid
}
