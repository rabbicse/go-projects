package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/application/authentication"
)

func AuthenticationMiddleware(loginTokenService *authentication.LoginTokenService) gin.HandlerFunc {
	return func(c *gin.Context) {

		token := c.GetHeader("Authorization")

		if token == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing login token"})
			return
		}

		token = strings.TrimPrefix(token, "Bearer ")

		loginToken, err := loginTokenService.Validate(token)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid login token"})
			return
		}

		// attach user to context
		c.Set("user_id", loginToken.UserID)

		c.Next()
	}
}
