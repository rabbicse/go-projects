package helpers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/argon2"
)

func DeriveVerifier(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

func ComputeProof(verifier, challenge []byte) []byte {
	h := hmac.New(sha256.New, verifier)
	h.Write(challenge)
	return h.Sum(nil)
}

func RandomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
