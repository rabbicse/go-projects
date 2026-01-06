package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/application/oauth"
)

type AuthorizeHandler struct {
	oauth oauth.AuthorizationService
}

func NewAuthorizeHandler(oauth oauth.AuthorizationService) *AuthorizeHandler {
	return &AuthorizeHandler{oauth: oauth}
}

func (h *AuthorizeHandler) Handle(c *gin.Context) {
	req := oauth.AuthorizeRequest{
		ResponseType: c.Query("response_type"),
		ClientID:     c.Query("client_id"),
		RedirectURI:  c.Query("redirect_uri"),
		Scope:        c.Query("scope"),
		State:        c.Query("state"),

		// ⚠️ TEMP: assume user already authenticated
		UserID: "user-123",
	}

	resp, err := h.oauth.Authorize(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	redirect := resp.RedirectURI +
		"?code=" + resp.Code +
		"&state=" + resp.State

	c.Redirect(http.StatusFound, redirect)
}
