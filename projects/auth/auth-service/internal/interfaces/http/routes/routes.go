package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/interfaces/http/handlers"
)

func Register(
	r *gin.Engine,
	authorize *handlers.AuthorizeHandler,
	token *handlers.TokenHandler,
) {
	r.GET("/authorize", authorize.Handle)
	r.POST("/token", token.Handle)
}
