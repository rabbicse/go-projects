package helpers

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func GenerateTOTP(secret string) (string, error) {
	return totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
		Period:    uint(30),
		Skew:      uint(1),
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
}
