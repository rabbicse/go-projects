package auth

import (
	"crypto/rand"
	"log"
	"time"

	"crypto/hmac"

	authchallenge "github.com/rabbicse/auth-service/internal/domain/challenge"
	"github.com/rabbicse/auth-service/internal/domain/common"
	"github.com/rabbicse/auth-service/internal/domain/user"
	"github.com/rabbicse/auth-service/pkg/helpers"
)

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
	log.Println("LOGIN SERVICE START CALLED")
	u, err := s.userRepo.FindByUsername(username)
	if err != nil {
		return nil, nil, common.ErrInvalidCredentials
	}

	challenge := make([]byte, 32)
	rand.Read(challenge)

	c := &authchallenge.Challenge{
		ID:        helpers.GenerateSecureTokenString(),
		UserID:    u.ID,
		Value:     challenge,
		ExpiresAt: s.clock().Add(2 * time.Minute),
	}

	log.Println("ABOUT TO SAVE CHALLENGE")
	s.challengeRepo.Save(c)

	return c, u.Salt, nil
}

func (s *ChallengeLoginService) Verify(
	username, challengeID string,
	proof []byte,
) (string, error) {

	u, err := s.userRepo.FindByUsername(username)
	if err != nil {
		return "", common.ErrInvalidCredentials
	}

	c, err := s.challengeRepo.Find(challengeID)
	if err != nil || c.Used || c.IsExpired(s.clock()) {
		return "", common.ErrInvalidProof
	}

	expected := helpers.ComputeProof([]byte(u.PasswordVerifier), c.Value)

	if !hmac.Equal(expected, proof) {
		return "", common.ErrInvalidProof
	}

	s.challengeRepo.MarkUsed(challengeID)

	return s.loginTokenService.Issue(u.ID)
}
