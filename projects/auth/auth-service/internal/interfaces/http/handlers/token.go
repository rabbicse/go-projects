package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/application/oauth"
)

type TokenHandler struct {
	oauth oauth.Service
}

func NewTokenHandler(oauth oauth.Service) *TokenHandler {
	return &TokenHandler{oauth: oauth}
}

func (h *TokenHandler) Handle(c *gin.Context) {
	req := oauth.TokenRequest{
		GrantType:    c.PostForm("grant_type"),
		Code:         c.PostForm("code"),
		RedirectURI:  c.PostForm("redirect_uri"),
		ClientID:     c.PostForm("client_id"),
		ClientSecret: c.PostForm("client_secret"),
	}

	resp, err := h.oauth.Token(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}
