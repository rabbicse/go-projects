package http

import (
	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/interfaces/http/handlers"
	"github.com/rabbicse/auth-service/internal/interfaces/http/routes"
)

func NewRouter(
	authorize *handlers.AuthorizeHandler,
	token *handlers.TokenHandler,
	oidc *handlers.OIDCHandler,
	jwks *handlers.JWKSHandler,
) *gin.Engine {
	r := gin.New()

	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	routes.Register(r, authorize, token, oidc, jwks)

	return r
}
