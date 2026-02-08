package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/infrastructure/security/oidc"
)

type DiscoveryHandler struct {
	provider *oidc.OidcProvider
}

func NewDiscoveryHandler(p *oidc.OidcProvider) *DiscoveryHandler {
	return &DiscoveryHandler{provider: p}
}

func (h *DiscoveryHandler) Handle(c *gin.Context) {

	c.Header(
		"Cache-Control",
		"public, max-age=3600",
	)

	c.JSON(http.StatusOK, h.provider)
}
