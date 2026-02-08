package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
)

type TokenIssuerService struct {
	signer token.TokenSigner
	store  token.RefreshStore
	issuer string
}

func NewTokenIssuerService(signer token.TokenSigner, store token.RefreshStore, issuer string) *TokenIssuerService {
	return &TokenIssuerService{
		signer: signer,
		store:  store,
		issuer: issuer,
	}
}

func (s *TokenIssuerService) GenerateAccessToken(
	userID string,
	clientID string,
	scopes []string,
) (string, time.Time, error) {

	now := time.Now()
	exp := now.Add(15 * time.Minute)

	claims := valueobjects.AccessClaims{
		Scope:    strings.Join(scopes, " "),
		ClientID: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   userID,
			Audience:  []string{clientID},
			Issuer:    s.issuer,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	tokenStr, err := s.signer.Sign(claims)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenStr, exp, nil
}

func (s *TokenIssuerService) GenerateRefreshToken(
	userID string,
	clientID string,
) (string, time.Time, error) {

	tokenStr, err := generateSecureToken(64)
	if err != nil {
		return "", time.Time{}, err
	}

	exp := time.Now().Add(30 * 24 * time.Hour)

	err = s.store.Save(
		tokenStr,
		userID,
		clientID,
		exp,
	)

	if err != nil {
		return "", time.Time{}, err
	}

	return tokenStr, exp, nil
}

func (s *TokenIssuerService) GenerateIDToken(
	userID string,
	clientID string,
	email string,
) (string, error) {

	now := time.Now()

	claims := valueobjects.IDClaims{
		Email:         email,
		EmailVerified: true,

		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  []string{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}

	return s.signer.Sign(claims)
}

func (s *TokenIssuerService) ValidateAccessToken(tokenStr string) (*valueobjects.AccessClaims, error) {

	token, err := jwt.ParseWithClaims(
		tokenStr,
		&valueobjects.AccessClaims{},
		func(t *jwt.Token) (interface{}, error) {

			if t.Method != jwt.SigningMethodRS256 {
				return nil, fmt.Errorf("unexpected signing method")
			}

			return s.signer.PublicKey(), nil
		},
	)

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*valueobjects.AccessClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func (s *TokenIssuerService) ValidateRefreshToken(
	token string,
) (*token.RefreshSession, error) {

	return s.store.Get(token)
}

func (s *TokenIssuerService) RotateRefreshToken(
	old string,
) (*token.RefreshSession, string, error) {

	session, err := s.store.Get(old)
	if err != nil {
		return nil, "", err
	}

	// delete old
	_ = s.store.Delete(old)

	// create new
	newToken, _, err := s.GenerateRefreshToken(
		session.UserID,
		session.ClientID,
	)

	if err != nil {
		return nil, "", err
	}

	return session, newToken, nil
}

func generateSecureToken(bytes int) (string, error) {
	b := make([]byte, bytes)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
