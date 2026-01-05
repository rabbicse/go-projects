package oidc

type IDTokenClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`

	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`

	Email string `json:"email,omitempty"`
}
