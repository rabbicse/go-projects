package jwt

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func PublicJWK(key *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Alg: "RS256",
		Use: "sig",
		Kid: "auth-key-1",
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}
