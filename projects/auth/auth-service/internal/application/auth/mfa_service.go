// internal/application/auth/mfa_service.go
package auth

import (
	"errors"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/rabbicse/auth-service/internal/domain/user"
)

var ErrInvalidMFA = errors.New("invalid mfa code")

type MFAService struct {
	userRepo user.Repository
}

func NewMFAService(userRepo user.Repository) *MFAService {
	return &MFAService{userRepo: userRepo}
}

// Step 1: Start enrollment (generate secret + QR)
func (s *MFAService) StartEnrollment(userID string) (secret string, qrURL string, err error) {
	u, err := s.userRepo.FindByID(userID)
	if err != nil {
		return "", "", err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AuthService",
		AccountName: u.Username,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", err
	}

	u.MFASecret = key.Secret()
	s.userRepo.Save(u)

	return key.Secret(), key.URL(), nil
}

// Step 2: Verify enrollment
func (s *MFAService) VerifyEnrollment(userID, code string) error {
	u, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	if !totp.Validate(code, u.MFASecret) {
		return ErrInvalidMFA
	}

	u.MFAEnabled = true
	s.userRepo.Save(u)
	return nil
}

// Step 3: Verify MFA during login
func (s *MFAService) VerifyLogin(userID, code string) error {
	u, err := s.userRepo.FindByID(userID)
	if err != nil {
		return err
	}

	valid, err := totp.ValidateCustom(
		code,
		u.MFASecret,
		time.Now(),
		totp.ValidateOpts{
			Period:    uint(30),
			Skew:      uint(1),
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)

	if err != nil || !valid {
		return ErrInvalidMFA
	}

	return nil
}
