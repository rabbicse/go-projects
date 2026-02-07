package token

import "crypto/rsa"

type TokenSigner interface {
	Sign(claims any) (string, error)
	PublicKey() *rsa.PublicKey
	Kid() string
}
