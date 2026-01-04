package usecases

import (
	"github.com/rabbicse/auth-service/internal/domain/services"
	"github.com/rabbicse/auth-service/pkg/errors"
)

// AuthorizeUseCase orchestrates the authorization flow
type AuthorizeUseCase struct {
	oauthService *services.OAuthService
}

func NewAuthorizeUseCase(oauthService *services.OAuthService) *AuthorizeUseCase {
	return &AuthorizeUseCase{oauthService: oauthService}
}

type AuthorizationRequest struct {
	ResponseType string `json:"response_type" binding:"required"`
	ClientID     string `json:"client_id" binding:"required"`
	RedirectURI  string `json:"redirect_uri" binding:"required"`
	Scope        string `json:"scope"`
	State        string `json:"state" binding:"required"`
}

type AuthorizationResponse struct {
	Code  string      `json:"code"`
	State string      `json:"state"`
	Error *OAuthError `json:"error,omitempty"`
}

type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
}

func (uc *AuthorizeUseCase) Execute(req AuthorizationRequest) (*AuthorizationResponse, error) {
	// Validate response_type
	if req.ResponseType != "code" {
		return &AuthorizationResponse{
			State: req.State,
			Error: &OAuthError{
				Code:        "unsupported_response_type",
				Description: "Only 'code' response_type is supported",
			},
		}, nil
	}

	// Parse scopes
	var scopes []string
	if req.Scope != "" {
		// Simple split - in production use proper scope parsing
		scopes = []string{req.Scope} // Simplified for example
	}

	// For demonstration, using a mock user ID
	// In real implementation, get from authenticated session
	userID := "authenticated-user-123"

	// Use domain service to create authorization
	auth, err := uc.oauthService.CreateAuthorization(
		req.ClientID,
		userID,
		req.RedirectURI,
		scopes,
	)

	if err != nil {
		// Map domain error to OAuth error
		domainErr, ok := err.(*errors.DomainError)
		if ok {
			return &AuthorizationResponse{
				State: req.State,
				Error: &OAuthError{
					Code:        domainErr.Code,
					Description: domainErr.Message,
				},
			}, nil
		}

		return &AuthorizationResponse{
			State: req.State,
			Error: &OAuthError{
				Code:        "server_error",
				Description: "Internal server error",
			},
		}, nil
	}

	return &AuthorizationResponse{
		Code:  auth.Code().Value(),
		State: req.State,
	}, nil
}
