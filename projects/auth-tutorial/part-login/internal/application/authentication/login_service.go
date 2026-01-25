package authentication

import (
	"crypto/rand"
	"errors"
	"log"
	"time"

	"crypto/hmac"

	authDomain "github.com/rabbicse/auth-service/internal/domain/aggregates/authentication"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/user"
	"github.com/rabbicse/auth-service/pkg/helpers"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidProof       = errors.New("invalid proof")
)

type LoginService struct {
	userRepo          user.UserRepository
	challengeRepo     authDomain.LoginChallengeRepository
	loginTokenService *LoginTokenService
}

func NewLoginService(
	userRepo user.UserRepository,
	challengeRepo authDomain.LoginChallengeRepository,
	loginTokenService *LoginTokenService,
) *LoginService {
	return &LoginService{
		userRepo:          userRepo,
		challengeRepo:     challengeRepo,
		loginTokenService: loginTokenService,
	}
}

func (s *LoginService) Start(username string) (*authDomain.LoginChallenge, []byte, error) {
	log.Println("LOGIN SERVICE START CALLED")

	u, err := s.userRepo.FindByUsername(username)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	rawChallenge := make([]byte, 32)
	rand.Read(rawChallenge)

	c := &authDomain.LoginChallenge{
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
		return "", ErrInvalidCredentials
	}
	log.Printf("Found user: %+v\n", u)

	c, err := s.challengeRepo.Find(challengeID)
	if err != nil || c.Used || c.IsExpired(time.Now()) {
		return "", ErrInvalidCredentials
	}
	log.Printf("Challenge found: %v\n", c.ID)

	log.Printf("SERVER salt (hex): %x", u.Salt)
	log.Printf("SERVER challenge (hex): %x", c.Value)
	log.Printf("SERVER verifier (hex): %x", u.PasswordVerifier)

	expected := helpers.ComputeProof(u.PasswordVerifier, c.Value)
	log.Printf("SERVER expected proof (hex): %x", expected)

	// expected := helpers.ComputeProof(u.PasswordVerifier, c.Value)
	if !hmac.Equal(expected, proof) {
		return "", ErrInvalidCredentials
	}

	s.challengeRepo.MarkUsed(challengeID)

	return s.loginTokenService.Issue(u.ID)
}
