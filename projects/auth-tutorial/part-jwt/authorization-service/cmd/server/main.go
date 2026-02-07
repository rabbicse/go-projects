package main

import (
	"fmt"
	"log"
	"time"

	"github.com/rabbicse/auth-service/internal/application/authentication"
	"github.com/rabbicse/auth-service/internal/application/oauth"
	tokenApp "github.com/rabbicse/auth-service/internal/application/token"
	"github.com/rabbicse/auth-service/internal/config"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/client"
	"github.com/rabbicse/auth-service/internal/infrastructure/persistence/memory"
	"github.com/rabbicse/auth-service/internal/infrastructure/security/crypto"
	"github.com/rabbicse/auth-service/internal/infrastructure/security/keys"
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

	// Initialize JWT token issuer
	keyPair, _ := keys.LoadKeyPair(
		"secrets/private.pem",
		"kid-2026-01",
	)
	signer := crypto.NewRSASigner(
		keyPair.PrivateKey,
		keyPair.PublicKey,
		keyPair.Kid,
	)
	refreshStore := memory.NewInMemoryRefreshStore()
	tokenIssuer := tokenApp.NewTokenIssuerService(
		signer,
		refreshStore,
		"https://auth.mycompany.com",
	)

	// Initialize Oauth 2.0 services and handlers
	clientRepo := memory.NewClientRepository([]*client.Client{
		{
			ID:           "client-123",
			SecretHash:   "secret", // replace with bcrypt later
			RedirectURIs: []string{"http://localhost:3000/callback"},
			Scopes:       []string{"openid", "profile", "email"},
			GrantTypes:   []client.GrantType{client.GrantAuthorizationCode},
			IsPublic:     false,
		},
	})
	authCodeRepo := memory.NewAuthCodeRepository()
	oauthService := oauth.NewOAuthService(clientRepo, authCodeRepo, time.Now)
	oAutheHandler := handlers.NewAuthorizeHandler(oauthService)

	tokenRepo := memory.NewTokenRepository()
	tokenService := oauth.NewTokenService(clientRepo, userRepo, authCodeRepo, tokenRepo, tokenIssuer, time.Now)
	tokenHandler := handlers.NewTokenHandler(tokenService)

	introspectionService := oauth.NewIntrospectionService(
		tokenRepo,
		time.Now,
	)

	introspectionHandler := handlers.NewIntrospectionHandler(introspectionService)

	// 2. Create HTTP router
	router := httpiface.NewRouter(registerHandler, loginHandler, oAutheHandler, tokenHandler, introspectionHandler)

	// 3. Start server
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)

	log.Printf("Auth server running on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}
