package http

import (
	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/interfaces/http/handlers"
)

func NewRouter(
	registerHandler *handlers.RegisterHandler,
	loginHandler *handlers.LoginHandler,
	oauthHandler *handlers.AuthorizeHandler,
	tokenHandler *handlers.TokenHandler,
	introspectionHandler *handlers.IntrospectionHandler,
	jwksHandler *handlers.JWKSHandler,
) *gin.Engine {
	r := gin.Default()

	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	// User registration route
	r.POST("/users/register", registerHandler.Register)

	// Login routes
	r.POST("/login/challenge", loginHandler.Start)
	r.POST("/login/verify", loginHandler.Verify)

	// Oauth 2.0 routes
	r.GET("/authorize", oauthHandler.Handle)
	r.POST("/token", tokenHandler.Handle)

	r.POST("/oauth/introspect", introspectionHandler.Introspect)

	// JWKS endpoint
	r.GET("/.well-known/jwks.json", jwksHandler.Handle)

	return r
}
