package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/application/usecases"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/authorization"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/client"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
	"github.com/rabbicse/auth-service/internal/domain/services"
	"github.com/rabbicse/auth-service/internal/infrastructure/persistence"
	"github.com/rabbicse/auth-service/internal/interfaces/controllers"
	"github.com/rabbicse/auth-service/internal/interfaces/middlewares"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {
	// Initialize factories
	clientFactory := client.NewClientFactory()
	authFactory := authorization.NewAuthorizationFactory()
	tokenFactory := token.NewTokenFactory()

	// Initialize repositories
	clientRepo := persistence.NewInMemoryClientRepository(clientFactory)
	authRepo := persistence.NewInMemoryAuthCodeRepository(authFactory)
	tokenRepo := persistence.NewInMemoryTokenRepository(tokenFactory)

	// Initialize domain service
	oauthService := services.NewOAuthService(
		clientRepo,
		authRepo,
		tokenRepo,
	)

	// Initialize use cases
	authorizeUseCase := usecases.NewAuthorizeUseCase(oauthService)
	tokenUseCase := usecases.NewTokenUseCase(oauthService)

	// Initialize controllers
	oauthController := controllers.NewOAuthController(
		authorizeUseCase,
		tokenUseCase,
	)

	// Setup Gin
	router := gin.Default()

	// OAuth endpoints
	router.GET("/oauth/authorize", oauthController.HandleAuthorization)
	router.POST("/oauth/token", oauthController.HandleToken)

	// Protected resources
	protected := router.Group("/api")
	protected.Use(middlewares.AuthMiddleware(oauthService))
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID, _ := c.Get("user_id")
			c.JSON(200, gin.H{
				"user_id": userID,
				"message": "Protected resource accessed",
			})
		})
	}

	// Swagger
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Health check
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	log.Println("OAuth DDD Server starting on :8080")
	log.Println("Test with: GET /oauth/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&state=xyz123&scope=read")

	if err := router.Run(":8080"); err != nil {
		log.Fatal("Server failed:", err)
	}
}
