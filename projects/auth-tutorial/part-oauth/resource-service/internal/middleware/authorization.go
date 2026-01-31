package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/resource-service/internal/application/token"
)

func AuthorizationMiddleware(validator *token.TokenValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing token"})
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")

		introspection, err := validator.Validate(token)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
			return
		}

		// Attach user info to context
		c.Set("sub", introspection.Sub)
		c.Set("scope", introspection.Scope)

		c.Next()
	}
}
