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
) *gin.Engine {
	r := gin.New()

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

	return r
}
