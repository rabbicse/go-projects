package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/application/dtos"
	"github.com/rabbicse/auth-service/internal/application/oauth"
)

type IntrospectionHandler struct {
	svc *oauth.IntrospectionService
}

func NewIntrospectionHandler(svc *oauth.IntrospectionService) *IntrospectionHandler {
	return &IntrospectionHandler{svc}
}

func (h *IntrospectionHandler) Introspect(c *gin.Context) {

	// ---- Client authentication (Resource Server) ----
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok || !isValidResourceServer(clientID, clientSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid client"})
		return
	}

	// ---- Parse token ----
	var req struct {
		Token string `json:"token" form:"token"`
	}

	if err := c.ShouldBind(&req); err != nil || req.Token == "" {
		c.JSON(http.StatusOK, dtos.IntrospectionResponse{Active: false})
		return
	}

	t, active := h.svc.Introspect(req.Token)
	if !active {
		c.JSON(http.StatusOK, dtos.IntrospectionResponse{Active: false})
		return
	}

	c.JSON(http.StatusOK, dtos.IntrospectionResponse{
		Active:   true,
		Sub:      t.UserID,
		ClientID: t.ClientID,
		Scope:    strings.Join(t.Scopes, " "),
		Exp:      t.ExpiresAt.Unix(),
	})
}

func isValidResourceServer(id, secret string) bool {
	return id == "resource-server" && secret == "secret"
}
