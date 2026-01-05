package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/interfaces/http/handlers"
)

func Register(
	r *gin.Engine,
	authorize *handlers.AuthorizeHandler,
	token *handlers.TokenHandler,
	oidc *handlers.OIDCHandler,
	jwks *handlers.JWKSHandler,
) {
	r.GET("/authorize", authorize.Handle)
	r.POST("/token", token.Handle)
	r.GET("/.well-known/openid-configuration", oidc.Discovery)
	r.GET("/jwks.json", jwks.Handle)
}
