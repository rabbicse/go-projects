package main

import (
	"fmt"
	"log"

	"github.com/rabbicse/auth-service/internal/application/authentication"
	"github.com/rabbicse/auth-service/internal/config"
	"github.com/rabbicse/auth-service/internal/infrastructure/persistence/memory"
	httpiface "github.com/rabbicse/auth-service/internal/interfaces/http"
	"github.com/rabbicse/auth-service/internal/interfaces/http/handlers"
)

func main() {
	// 1. Load configuration
	cfg := config.Load()

	// Add user repository and registration service initialization here
	userRepo := memory.NewUserRepository(nil) // No seed data, we will add users via registration
	registrationService := authentication.NewUserRegistrationService(userRepo)

	// Initialize registration handler with the service
	registerHandler := handlers.NewRegisterHandler(registrationService)

	// Initialize login service and handler
	challengeRepo := memory.NewLoginChallengeRepo()
	loginTokenRepo := memory.NewLoginTokenRepo()
	loginTokenService := authentication.NewLoginTokenService(loginTokenRepo)
	loginService := authentication.NewLoginService(userRepo, challengeRepo, loginTokenService)
	loginHandler := handlers.NewLoginHandler(loginService)

	// 2. Create HTTP router
	router := httpiface.NewRouter(registerHandler, loginHandler)

	// 3. Start server
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)

	log.Printf("Auth server running on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}
