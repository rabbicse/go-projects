package usecases

import (
	"strings"

	"github.com/rabbicse/auth-service/internal/domain/services"
	"github.com/rabbicse/auth-service/internal/domain/valueobjects"
	"github.com/rabbicse/auth-service/pkg/errors"
)

// TokenUseCase orchestrates the token exchange flow
type TokenUseCase struct {
	oauthService *services.OAuthService
}

// NewTokenUseCase creates a new TokenUseCase instance
func NewTokenUseCase(oauthService *services.OAuthService) *TokenUseCase {
	return &TokenUseCase{oauthService: oauthService}
}

// TokenRequest represents RFC 6749 Section 4.1.3 request
type TokenRequest struct {
	GrantType    string `json:"grant_type" binding:"required"`
	Code         string `json:"code" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenResponse represents RFC 6749 Section 5.1 response
type TokenResponse struct {
	AccessToken  string      `json:"access_token"`
	TokenType    string      `json:"token_type"`
	ExpiresIn    int         `json:"expires_in"`
	RefreshToken string      `json:"refresh_token,omitempty"`
	Scope        string      `json:"scope,omitempty"`
	Error        *OAuthError `json:"error,omitempty"`
}

// Execute handles token exchange requests
func (uc *TokenUseCase) Execute(req TokenRequest) (*TokenResponse, error) {
	// Validate grant type
	grantType, err := valueobjects.NewGrantType(req.GrantType)
	if err != nil {
		return &TokenResponse{
			Error: &OAuthError{
				Code:        "unsupported_grant_type",
				Description: err.Error(),
			},
		}, nil
	}

	// Handle different grant types
	switch grantType.Value {
	case "authorization_code":
		return uc.handleAuthorizationCode(req)
	case "refresh_token":
		return uc.handleRefreshToken(req)
	default:
		return &TokenResponse{
			Error: &OAuthError{
				Code:        "unsupported_grant_type",
				Description: "Grant type not supported",
			},
		}, nil
	}
}

// handleAuthorizationCode handles authorization_code grant type
func (uc *TokenUseCase) handleAuthorizationCode(req TokenRequest) (*TokenResponse, error) {
	// Exchange authorization code for tokens
	tokenAgg, err := uc.oauthService.ExchangeAuthorizationForTokens(
		req.Code,
		req.ClientID,
		req.ClientSecret,
		req.RedirectURI,
	)

	if err != nil {
		return uc.mapErrorToResponse(err), nil
	}

	// Build response
	response := &TokenResponse{
		AccessToken: tokenAgg.AccessToken().Value,
		TokenType:   tokenAgg.TokenType().Value,
		ExpiresIn:   tokenAgg.ExpiresIn().Value,
		Scope:       strings.Join(tokenAgg.ScopesString(), " "),
	}

	// Include refresh token if available
	if tokenAgg.RefreshToken() != nil {
		response.RefreshToken = tokenAgg.RefreshTokenValue()
	}

	return response, nil
}

// handleRefreshToken handles refresh_token grant type
func (uc *TokenUseCase) handleRefreshToken(req TokenRequest) (*TokenResponse, error) {
	if req.RefreshToken == "" {
		return &TokenResponse{
			Error: &OAuthError{
				Code:        "invalid_request",
				Description: "refresh_token parameter required",
			},
		}, nil
	}

	// Parse requested scopes (if any)
	var requestedScopes []string
	if req.Scope != "" {
		requestedScopes = strings.Split(req.Scope, " ")
	}

	// Refresh the access token
	tokenAgg, err := uc.oauthService.RefreshAccessToken(
		req.RefreshToken,
		req.ClientID,
		req.ClientSecret,
		requestedScopes,
	)

	if err != nil {
		return uc.mapErrorToResponse(err), nil
	}

	// Build response
	response := &TokenResponse{
		AccessToken: tokenAgg.AccessToken().Value,
		TokenType:   tokenAgg.TokenType().Value,
		ExpiresIn:   tokenAgg.ExpiresIn().Value,
		Scope:       strings.Join(tokenAgg.ScopesString(), " "),
	}

	// Include refresh token if available
	if tokenAgg.RefreshToken() != nil {
		response.RefreshToken = tokenAgg.RefreshTokenValue()
	}

	return response, nil
}

// mapErrorToResponse converts domain errors to OAuth error responses
func (uc *TokenUseCase) mapErrorToResponse(err error) *TokenResponse {
	domainErr, ok := err.(*errors.DomainError)
	if ok {
		return &TokenResponse{
			Error: &OAuthError{
				Code:        domainErr.Code,
				Description: domainErr.Message,
			},
		}
	}

	// Handle specific errors
	if err.Error() == "client not found" {
		return &TokenResponse{
			Error: &OAuthError{
				Code:        "invalid_client",
				Description: "Client not found",
			},
		}
	}

	if strings.Contains(err.Error(), "authorization code") {
		return &TokenResponse{
			Error: &OAuthError{
				Code:        "invalid_grant",
				Description: "Invalid authorization code",
			},
		}
	}

	if strings.Contains(err.Error(), "refresh token") {
		return &TokenResponse{
			Error: &OAuthError{
				Code:        "invalid_grant",
				Description: "Invalid refresh token",
			},
		}
	}

	return &TokenResponse{
		Error: &OAuthError{
			Code:        "server_error",
			Description: "Internal server error",
		},
	}
}

// // OAuthError represents OAuth 2.0 error response
// type OAuthError struct {
// 	Code        string `json:"error"`
// 	Description string `json:"error_description,omitempty"`
// 	URI         string `json:"error_uri,omitempty"`
// }
