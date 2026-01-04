package middlewares

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/domain/services"
)

// AuthMiddleware validates Bearer tokens for protected endpoints
func AuthMiddleware(authService *services.OAuthService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "Authorization header is required",
			})
			ctx.Abort()
			return
		}

		// Extract Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "Authorization header must be 'Bearer {token}'",
			})
			ctx.Abort()
			return
		}

		accessToken := parts[1]

		// Validate token using domain service
		token, err := authService.ValidateAccessToken(accessToken)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": err.Error(),
			})
			ctx.Abort()
			return
		}

		// Set token context for downstream handlers
		ctx.Set("user_id", token.UserID().Value())
		ctx.Set("client_id", token.ClientID().Value())
		ctx.Set("scopes", token.ScopesString())

		ctx.Next()
	}
}
