package controllers

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/application/usecases"
)

// OAuthController handles HTTP requests for OAuth 2.0 endpoints
type OAuthController struct {
	authorizeUseCase *usecases.AuthorizeUseCase
	tokenUseCase     *usecases.TokenUseCase
}

// NewOAuthController creates a new OAuthController instance
func NewOAuthController(
	authorizeUseCase *usecases.AuthorizeUseCase,
	tokenUseCase *usecases.TokenUseCase,
) *OAuthController {
	return &OAuthController{
		authorizeUseCase: authorizeUseCase,
		tokenUseCase:     tokenUseCase,
	}
}

// HandleAuthorization handles GET /oauth/authorize (RFC 6749 Section 4.1.1)
func (c *OAuthController) HandleAuthorization(ctx *gin.Context) {
	// Parse query parameters manually since they come from URL, not body
	req := usecases.AuthorizationRequest{
		ResponseType: ctx.Query("response_type"),
		ClientID:     ctx.Query("client_id"),
		RedirectURI:  ctx.Query("redirect_uri"),
		Scope:        ctx.Query("scope"),
		State:        ctx.Query("state"),
	}

	// Validate required fields
	if req.ResponseType == "" || req.ClientID == "" || req.RedirectURI == "" || req.State == "" {
		ctx.JSON(http.StatusBadRequest, ErrorResponse{
			Error:       "invalid_request",
			Description: "Missing required parameters: response_type, client_id, redirect_uri, and state are required",
		})
		return
	}

	// Execute use case
	response, err := c.authorizeUseCase.Execute(req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:       "server_error",
			Description: err.Error(),
		})
		return
	}

	// Handle error response
	if response.Error != nil {
		// Redirect with error in query parameters
		redirectURI := req.RedirectURI + "?error=" + url.QueryEscape(response.Error.Code)
		if response.Error.Description != "" {
			redirectURI += "&error_description=" + url.QueryEscape(response.Error.Description)
		}
		if response.State != "" {
			redirectURI += "&state=" + url.QueryEscape(response.State)
		}

		ctx.Redirect(http.StatusFound, redirectURI)
		return
	}

	// Success: redirect with authorization code
	redirectURI := req.RedirectURI + "?code=" + url.QueryEscape(response.Code)
	if response.State != "" {
		redirectURI += "&state=" + url.QueryEscape(response.State)
	}

	ctx.Redirect(http.StatusFound, redirectURI)
}

// HandleToken handles POST /oauth/token (RFC 6749 Section 4.1.3)
func (c *OAuthController) HandleToken(ctx *gin.Context) {
	var req usecases.TokenRequest

	// For token endpoint, use form binding (POST request with form data)
	if err := ctx.ShouldBind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, ErrorResponse{
			Error:       "invalid_request",
			Description: err.Error(),
		})
		return
	}

	// Execute use case
	response, err := c.tokenUseCase.Execute(req)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:       "server_error",
			Description: err.Error(),
		})
		return
	}

	// Return token response
	ctx.JSON(http.StatusOK, response)
}

// ErrorResponse represents OAuth 2.0 error response
type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}
