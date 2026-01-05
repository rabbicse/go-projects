package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/rabbicse/auth-service/internal/application/oidc"
	"github.com/rabbicse/auth-service/internal/domain/authcode"
	"github.com/rabbicse/auth-service/internal/domain/client"
	"github.com/rabbicse/auth-service/internal/domain/token"
	"github.com/rabbicse/auth-service/internal/domain/user"
)

type TokenService struct {
	clientRepo   client.Repository
	userRepo     user.Repository
	authCodeRepo authcode.Repository
	tokenRepo    token.Repository
	oidc         oidc.Service
	clock        func() time.Time
}

// Authorize implements Service.
func (s *TokenService) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResponse, error) {
	panic("unimplemented")
}

func NewTokenService(
	clientRepo client.Repository,
	authCodeRepo authcode.Repository,
	tokenRepo token.Repository,
	clock func() time.Time,
) *TokenService {
	return &TokenService{
		clientRepo:   clientRepo,
		authCodeRepo: authCodeRepo,
		tokenRepo:    tokenRepo,
		clock:        clock,
	}
}

func (s *TokenService) Token(
	ctx context.Context,
	req TokenRequest,
) (*TokenResponse, error) {

	if req.GrantType != "authorization_code" {
		return nil, ErrUnsupportedGrantType
	}

	// 1. Load client
	c, err := s.clientRepo.FindByID(ctx, req.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	// 2. Authenticate client (confidential clients)
	if !c.IsPublic {
		if !verifySecret(req.ClientSecret, c.SecretHash) {
			return nil, ErrClientAuthFailed
		}
	}

	// 3. Consume authorization code (one-time)
	authCode, err := s.authCodeRepo.Consume(ctx, req.Code)
	if err != nil {
		return nil, ErrInvalidAuthCode
	}

	// 4. Validate auth code
	if authCode.ClientID != c.ID {
		return nil, ErrInvalidAuthCode
	}

	if authCode.RedirectURI != req.RedirectURI {
		return nil, ErrInvalidRedirectURI
	}

	if authCode.IsExpired(s.clock()) {
		return nil, ErrInvalidAuthCode
	}

	// 5. Issue tokens
	accessToken, _ := generateSecureToken(32)
	refreshToken, _ := generateSecureToken(32)

	expiresAt := s.clock().Add(1 * time.Hour)

	tok := &token.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     c.ID,
		UserID:       authCode.UserID,
		Scopes:       authCode.Scopes,
		ExpiresAt:    expiresAt,
	}

	if err := s.tokenRepo.Save(ctx, tok); err != nil {
		return nil, err
	}

	var idToken string

	for _, scope := range authCode.Scopes {
		if scope == "openid" {
			user, err := s.userRepo.FindByID(ctx, authCode.UserID)
			if err != nil {
				return nil, err
			}

			idToken, err = s.oidc.GenerateIDToken(
				user,
				c.ID,
				authCode.Scopes,
			)
			if err != nil {
				return nil, err
			}
			break
		}
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(expiresAt).Seconds()),
		Scope:        strings.Join(authCode.Scopes, " "),
		IDToken:      idToken, // ✅ now populated
	}, nil
}

func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func verifySecret(raw, hash string) bool {
	return raw == hash // TEMP – replace with bcrypt
}
