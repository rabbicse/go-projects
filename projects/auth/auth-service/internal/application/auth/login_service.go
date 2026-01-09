package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"time"

	authchallenge "github.com/rabbicse/auth-service/internal/domain/challenge"
	"github.com/rabbicse/auth-service/internal/domain/login"
	"github.com/rabbicse/auth-service/internal/domain/user"
	"github.com/rabbicse/auth-service/pkg/helpers"
)

var ErrInvalidLogin = errors.New("invalid login")

type LoginService struct {
	userRepo      user.Repository
	challengeRepo interface {
		Save(*authchallenge.Challenge)
		Find(string) (*authchallenge.Challenge, error)
		MarkUsed(string)
	}
	loginTokenService *LoginTokenService
}

func (s *LoginService) Start(username string) (*authchallenge.Challenge, []byte, error) {
	u, err := s.userRepo.FindByUsername(username)
	if err != nil {
		return nil, nil, ErrInvalidLogin
	}

	challenge := make([]byte, 32)
	rand.Read(challenge)

	c := &authchallenge.Challenge{
		ID:        helpers.RandomToken(),
		UserID:    u.ID,
		Value:     challenge,
		ExpiresAt: time.Now().Add(2 * time.Minute),
	}

	s.challengeRepo.Save(c)

	return c, u.Salt, nil
}

func (s *LoginService) Verify(username, challengeID string, proof []byte) (string, error) {
	u, err := s.userRepo.FindByUsername(username)
	if err != nil {
		return "", ErrInvalidLogin
	}

	c, err := s.challengeRepo.Find(challengeID)
	if err != nil || c.Used || c.IsExpired(time.Now()) {
		return "", ErrInvalidLogin
	}

	expected := helpers.ComputeProof(u.Verifier, c.Value)
	if !hmac.Equal(expected, proof) {
		return "", ErrInvalidLogin
	}

	s.challengeRepo.MarkUsed(challengeID)
	return s.loginTokenService.Issue(u.ID)
}

func (s *LoginTokenService) Issue(userID string) (string, error) {
	token := &login.Token{
		Value:     helpers.RandomToken(), // 256-bit cryptographic random
		UserID:    userID,
		ExpiresAt: s.clock().Add(10 * time.Minute),
		Used:      false,
	}

	s.repo.Save(token)
	return token.Value, nil
}
