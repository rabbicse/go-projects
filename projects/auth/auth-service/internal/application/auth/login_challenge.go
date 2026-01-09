package auth

import (
	"crypto/rand"
	"errors"
	"time"

	"crypto/hmac"

	authchallenge "github.com/rabbicse/auth-service/internal/domain/challenge"
	"github.com/rabbicse/auth-service/internal/domain/user"
)

var ErrInvalidProof = errors.New("invalid proof")

type ChallengeLoginService struct {
	userRepo      user.Repository
	challengeRepo interface {
		Save(*authchallenge.Challenge)
		Find(string) (*authchallenge.Challenge, error)
		MarkUsed(string)
	}
	loginTokenService *LoginTokenService
	clock             func() time.Time
}

func (s *ChallengeLoginService) Start(username string) (*authchallenge.Challenge, []byte, error) {
	u, err := s.userRepo.FindByUsername(username)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	challenge := make([]byte, 32)
	rand.Read(challenge)

	c := &authchallenge.Challenge{
		ID:        generateSecureTokenString(),
		UserID:    u.ID,
		Value:     challenge,
		ExpiresAt: s.clock().Add(2 * time.Minute),
	}

	s.challengeRepo.Save(c)

	return c, u.Salt, nil
}

func (s *ChallengeLoginService) Verify(
	username, challengeID string,
	proof []byte,
) (string, error) {

	u, err := s.userRepo.FindByUsername(username)
	if err != nil {
		return "", ErrInvalidCredentials
	}

	c, err := s.challengeRepo.Find(challengeID)
	if err != nil || c.Used || c.IsExpired(s.clock()) {
		return "", ErrInvalidProof
	}

	expected := computeProof([]byte(u.PasswordVerifier), c.Value)

	if !hmac.Equal(expected, proof) {
		return "", ErrInvalidProof
	}

	s.challengeRepo.MarkUsed(challengeID)

	return s.loginTokenService.Issue(u.ID)
}
