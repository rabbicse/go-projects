package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/authcode"
	"github.com/rabbicse/auth-service/internal/domain/client"
)

type OAuthService struct {
	clientRepo   client.Repository
	authCodeRepo authcode.Repository
	clock        func() time.Time
}

// Token implements Service.
func (s *OAuthService) Token(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	panic("unimplemented")
}

func NewOAuthService(
	clientRepo client.Repository,
	authCodeRepo authcode.Repository,
	clock func() time.Time,
) *OAuthService {
	return &OAuthService{
		clientRepo:   clientRepo,
		authCodeRepo: authCodeRepo,
		clock:        clock,
	}
}

func (s *OAuthService) Authorize(
	ctx context.Context,
	req AuthorizeRequest,
) (*AuthorizeResponse, error) {

	// 1. response_type validation
	if req.ResponseType != "code" {
		return nil, ErrUnsupportedResponseType
	}

	// 2. Load client
	c, err := s.clientRepo.FindByID(ctx, req.ClientID)
	if err != nil {
		return nil, ErrInvalidClient
	}

	// 3. Redirect URI validation
	if !c.AllowsRedirect(req.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}

	// 4. Scope validation
	scopes := strings.Fields(req.Scope)
	for _, scope := range scopes {
		if !c.AllowsScope(scope) {
			return nil, ErrInvalidScope
		}
	}

	// 5. Generate authorization code
	code, err := generateSecureCode(32)
	if err != nil {
		return nil, err
	}

	authCode := &authcode.AuthorizationCode{
		Code:        code,
		ClientID:    c.ID,
		UserID:      req.UserID,
		RedirectURI: req.RedirectURI,
		Scopes:      scopes,
		ExpiresAt:   s.clock().Add(5 * time.Minute),
	}

	// 6. Persist authorization code
	if err := s.authCodeRepo.Save(ctx, authCode); err != nil {
		return nil, err
	}

	// 7. Build response
	return &AuthorizeResponse{
		RedirectURI: req.RedirectURI,
		Code:        code,
		State:       req.State,
	}, nil
}

func generateSecureCode(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
