package oauth

import (
	"context"
	"crypto/subtle"
	"log"
	"strings"
	"time"

	"github.com/rabbicse/auth-service/internal/application"
	"github.com/rabbicse/auth-service/internal/application/dtos"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/client"
	oauthDomain "github.com/rabbicse/auth-service/internal/domain/aggregates/oauth"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
	tokenDomain "github.com/rabbicse/auth-service/internal/domain/aggregates/token"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/user"
)

type TokenService struct {
	clientRepo   client.ClientRepository
	userRepo     user.UserRepository
	authCodeRepo oauthDomain.AuthorizationCodeRepository
	tokenRepo    tokenDomain.TokenRepository
	tokenIssuer  token.TokenIssuer
	clock        func() time.Time
}

func NewTokenService(
	clientRepo client.ClientRepository,
	userRepo user.UserRepository,
	authCodeRepo oauthDomain.AuthorizationCodeRepository,
	tokenRepo tokenDomain.TokenRepository,
	tokenIssuer token.TokenIssuer,
	clock func() time.Time,
) *TokenService {
	return &TokenService{
		clientRepo:   clientRepo,
		userRepo:     userRepo,
		authCodeRepo: authCodeRepo,
		tokenRepo:    tokenRepo,
		tokenIssuer:  tokenIssuer,
		clock:        clock,
	}
}

func (s *TokenService) Token(
	ctx context.Context,
	req dtos.TokenRequest,
) (*dtos.TokenResponse, error) {

	// ✅ Grant validation
	switch req.GrantType {
	case "authorization_code":
		return s.handleAuthorizationCode(ctx, req)
	case "refresh_token":
		return s.handleRefresh(ctx, req)
	default:
		return nil, application.ErrUnsupportedGrantType
	}
}

func (s *TokenService) handleAuthorizationCode(
	ctx context.Context,
	req dtos.TokenRequest,
) (*dtos.TokenResponse, error) {
	// ✅ Load client
	c, err := s.clientRepo.FindByID(req.ClientID)
	if err != nil {
		return nil, application.ErrInvalidClient
	}
	log.Printf("Client: %v", c)

	// ✅ Ensure client supports this grant
	if !c.SupportsGrant(client.GrantAuthorizationCode) {
		return nil, application.ErrUnauthorizedClient
	}

	// ✅ Authenticate confidential client
	if !c.IsPublic {
		if !verifySecret(req.ClientSecret, c.SecretHash) {
			return nil, application.ErrClientAuthFailed
		}
	}

	// ✅ Fetch authorization code
	// authCode, err := s.authCodeRepo.Get(req.Code)
	authCode, err := s.authCodeRepo.Consume(req.Code)
	if err != nil {
		return nil, application.ErrInvalidAuthCode
	}

	// ✅ Validate code ownership
	if authCode.ClientID != c.ID {
		return nil, application.ErrInvalidAuthCode
	}

	if authCode.RedirectURI != req.RedirectURI {
		return nil, application.ErrInvalidRedirectURI
	}

	if authCode.IsExpired(s.clock()) {
		return nil, application.ErrInvalidAuthCode
	}

	log.Printf("Auth Code: %v", authCode)

	// ✅ Load user (needed for ID token)
	log.Println("Looking for user:", authCode.UserID)
	u, err := s.userRepo.FindByID(authCode.UserID)
	log.Println("User lookup result:", u, err)
	if err != nil {
		return nil, application.ErrInvalidUser
	}

	// ✅ Generate Access Token
	accessToken, expiresAt, err :=
		s.tokenIssuer.GenerateAccessToken(
			u.ID,
			c.ID,
			authCode.Scopes,
		)
	if err != nil {
		return nil, err
	}

	// ✅ Generate Refresh Token
	refreshToken, _, err :=
		s.tokenIssuer.GenerateRefreshToken(
			u.ID,
			c.ID,
		)
	if err != nil {
		return nil, err
	}

	// ✅ Issue ID Token ONLY when openid scope present
	var idToken string

	if hasScope(authCode.Scopes, "openid") {

		idToken, err = s.tokenIssuer.GenerateIDToken(
			u.ID,
			c.ID,
			u.Email,
		)

		if err != nil {
			return nil, err
		}
	}

	// ✅ Persist token
	tok := &tokenDomain.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		ClientID:     c.ID,
		UserID:       u.ID,
		Scopes:       authCode.Scopes,
		ExpiresAt:    expiresAt,
	}

	if err := s.tokenRepo.Save(tok); err != nil {
		return nil, err
	}

	return &dtos.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(expiresAt).Seconds()),
		Scope:        strings.Join(authCode.Scopes, " "),
	}, nil
}

func (s *TokenService) handleRefresh(
	ctx context.Context,
	req dtos.TokenRequest,
) (*dtos.TokenResponse, error) {

	log.Println("REFRESH RECEIVED:", req.RefreshToken)

	if req.RefreshToken == "" {
		return nil, application.ErrInvalidRefreshToken
	}

	// ✅ rotate using issuer
	session, newRefresh, err :=
		s.tokenIssuer.RotateRefreshToken(req.RefreshToken)

	if err != nil {
		return nil, application.ErrInvalidRefreshToken
	}

	accessToken, exp, err :=
		s.tokenIssuer.GenerateAccessToken(
			session.UserID,
			session.ClientID,
			session.Scopes, // IMPORTANT — store scopes!
		)
	if err != nil {
		return nil, err
	}

	return &dtos.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(exp).Seconds()),
	}, nil
}

////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////

func verifySecret(raw, hash string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(raw),
		[]byte(hash),
	) == 1
}

func hasScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}
