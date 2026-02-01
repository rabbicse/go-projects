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
	loginHandler *handlers.LoginHandler,
	registerHandler *handlers.RegisterHandler,
	mfa *handlers.MFAHandler,
) {
	r.GET("/authorize", authorize.Handle)
	r.POST("/token", token.Handle)
	r.GET("/.well-known/openid-configuration", oidc.Discovery)
	r.GET("/jwks.json", jwks.Handle)
	r.POST("/login/challenge", loginHandler.Start)
	r.POST("/login/verify", loginHandler.Verify)
	r.POST("/users/register", registerHandler.Register)

	// MFA routes
	r.POST("/mfa/enroll/start", mfa.StartEnroll)
	r.POST("/mfa/enroll/verify", mfa.VerifyEnroll)
	r.POST("/mfa/verify", mfa.VerifyLogin)
}
