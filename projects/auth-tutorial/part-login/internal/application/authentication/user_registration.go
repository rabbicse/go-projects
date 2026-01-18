package authentication

import (
	"encoding/base64"
	"errors"

	"github.com/google/uuid"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/user"
)

var ErrUserAlreadyExists = errors.New("user already exists")

type UserRegistrationService struct {
	repo user.Repository
}

func NewUserRegistrationService(repo user.Repository) *UserRegistrationService {
	return &UserRegistrationService{repo: repo}
}

func (s *UserRegistrationService) Register(username, email, saltB64, verifierB64 string) (*user.User, error) {
	if _, err := s.repo.FindByUsername(username); err == nil {
		return nil, ErrUserAlreadyExists
	}

	salt, err := base64.RawURLEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, errors.New("invalid salt encoding")
	}

	verifier, err := base64.RawURLEncoding.DecodeString(verifierB64)
	if err != nil {
		return nil, errors.New("invalid verifier encoding")
	}

	u := &user.User{
		ID:               uuid.NewString(),
		Username:         username,
		Email:            email,
		Salt:             salt,
		PasswordVerifier: verifier,
		IsVerified:       true,
	}

	if err := s.repo.Save(u); err != nil {
		return nil, err
	}

	return u, nil
}
