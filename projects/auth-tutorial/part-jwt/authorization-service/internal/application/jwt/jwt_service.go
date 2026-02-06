package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
)

type JWTService struct {
	cfg token.JWTConfig
}

func NewJWTService(cfg token.JWTConfig) *JWTService {
	return &JWTService{cfg: cfg}
}

func (s *JWTService) CreateAccessToken(sub, scope string, roles []string, clientID string) (string, time.Time, error) {
	exp := time.Now().Add(s.cfg.AccessTTL)

	claims := AccessClaims{
		Sub:      sub,
		Scope:    scope,
		Roles:    roles,
		ClientID: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.cfg.Issuer,
			// Subject:   sub,           // many libs auto-set from Sub
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.cfg.AccessSecret)
	if err != nil {
		return "", time.Time{}, err
	}

	return signed, exp, nil
}

func (s *JWTService) CreateRefreshToken(sub string) (string, time.Time, error) {
	exp := time.Now().Add(s.cfg.RefreshTTL)
	claims := RefreshClaims{
		Sub: sub,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.cfg.Issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(s.cfg.RefreshSecret)
	return signed, exp, err
}

func (s *JWTService) ValidateAccessToken(tokenStr string) (*AccessClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected alg: %v", t.Header["alg"])
		}
		return s.cfg.AccessSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*AccessClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}
