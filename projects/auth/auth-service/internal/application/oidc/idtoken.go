package oidc

import (
	"time"

	"github.com/rabbicse/auth-service/internal/domain/user"
)

type TokenSigner interface {
	Sign(claims IDTokenClaims) (string, error)
}

type OIDCService struct {
	issuer string
	signer TokenSigner
	clock  func() time.Time
}

func NewOIDCService(
	issuer string,
	signer TokenSigner,
	clock func() time.Time,
) *OIDCService {
	return &OIDCService{
		issuer: issuer,
		signer: signer,
		clock:  clock,
	}
}

func (s *OIDCService) GenerateIDToken(
	user *user.User,
	clientID string,
	scopes []string,
) (string, error) {

	now := s.clock()

	claims := IDTokenClaims{
		Issuer:    s.issuer,
		Subject:   user.ID,
		Audience:  clientID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(15 * time.Minute).Unix(),
	}

	for _, scope := range scopes {
		if scope == "email" {
			claims.Email = user.Email
		}
	}

	return s.signer.Sign(claims)
}
