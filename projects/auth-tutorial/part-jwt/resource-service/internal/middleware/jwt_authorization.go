package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/resource-service/internal/application/token"
)

func JWTAuthorizationMiddleware(
	validator *token.JWTTokenValidator,
) gin.HandlerFunc {

	return func(c *gin.Context) {

		auth := c.GetHeader("Authorization")

		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{"error": "missing token"},
			)
			return
		}

		tokenString := strings.TrimPrefix(auth, "Bearer ")

		token, err := validator.Validate(tokenString)
		if err != nil {

			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{"error": "invalid token"},
			)
			return
		}

		// Extract claims safely
		sub, _ := token.Get("sub")
		scope, _ := token.Get("scope")

		// Attach to context
		c.Set("sub", sub)
		c.Set("scope", scope)

		c.Next()
	}
}
