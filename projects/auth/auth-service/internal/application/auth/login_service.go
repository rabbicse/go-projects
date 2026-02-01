package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"log"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/challenge"
	authchallenge "github.com/rabbicse/auth-service/internal/domain/challenge"
	"github.com/rabbicse/auth-service/internal/domain/login"
	"github.com/rabbicse/auth-service/internal/domain/user"
	"github.com/rabbicse/auth-service/pkg/helpers"
)

var ErrInvalidLogin = errors.New("invalid login")

type LoginService struct {
	userRepo          user.Repository
	challengeRepo     challenge.Repository
	loginTokenService *LoginTokenService
}

func NewLoginService(
	userRepo user.Repository,
	challengeRepo challenge.Repository,
	loginTokenService *LoginTokenService,
) *LoginService {
	return &LoginService{
		userRepo:          userRepo,
		challengeRepo:     challengeRepo,
		loginTokenService: loginTokenService,
	}
}

func (s *LoginService) Start(username string) (*authchallenge.Challenge, []byte, error) {
	log.Println("LOGIN SERVICE START CALLED")

	u, err := s.userRepo.FindByUsername(username)
	if err != nil {
		return nil, nil, ErrInvalidLogin
	}

	rawChallenge := make([]byte, 32)
	rand.Read(rawChallenge)

	c := &authchallenge.Challenge{
		ID:        helpers.GenerateSecureTokenString(),
		UserID:    u.ID,
		Value:     rawChallenge,
		ExpiresAt: time.Now().Add(2 * time.Minute),
		Used:      false,
	}

	log.Println("ABOUT TO SAVE CHALLENGE:", c.ID)
	s.challengeRepo.Save(c)
	log.Println("CHALLENGE SAVED")

	return c, u.Salt, nil
}

func (s *LoginService) Verify(username, challengeID string, proof []byte) (string, error) {
	u, err := s.userRepo.FindByUsername(username)
	if err != nil {
		return "", ErrInvalidLogin
	}
	log.Printf("Found user: %+v\n", u)

	c, err := s.challengeRepo.Find(challengeID)
	if err != nil || c.Used || c.IsExpired(time.Now()) {
		return "", ErrInvalidLogin
	}
	log.Printf("Challenge found: %v\n", c.ID)

	log.Printf("SERVER salt (hex): %x", u.Salt)
	log.Printf("SERVER challenge (hex): %x", c.Value)
	log.Printf("SERVER verifier (hex): %x", u.PasswordVerifier)

	expected := helpers.ComputeProof(u.PasswordVerifier, c.Value)
	log.Printf("SERVER expected proof (hex): %x", expected)

	// expected := helpers.ComputeProof(u.PasswordVerifier, c.Value)
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
		ExpiresAt: s.clock().Add(20 * time.Minute),
		Used:      false,
		AuthLevel: login.AuthPassword,
	}

	s.repo.Save(token)
	return token.Value, nil
}
