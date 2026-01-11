package main

import (
	"fmt"
	"log"
	"time"

	"github.com/rabbicse/auth-service/internal/application/auth"
	"github.com/rabbicse/auth-service/internal/application/oauth"
	"github.com/rabbicse/auth-service/internal/application/oidc"
	"github.com/rabbicse/auth-service/internal/config"
	"github.com/rabbicse/auth-service/internal/domain/client"
	jwtinfra "github.com/rabbicse/auth-service/internal/infrastructure/jwt"
	"github.com/rabbicse/auth-service/internal/infrastructure/persistence/memory"
	httpiface "github.com/rabbicse/auth-service/internal/interfaces/http"
	"github.com/rabbicse/auth-service/internal/interfaces/http/handlers"
)

func main() {
	// ---------------------------
	// Load config
	// ---------------------------
	cfg := config.Load()
	issuer := fmt.Sprintf("http://%s:%s", cfg.Server.Host, cfg.Server.Port)

	// ---------------------------
	// JWT keys (generated once)
	// ---------------------------
	privateKey, err := jwtinfra.GenerateRSAKey()
	if err != nil {
		log.Fatal(err)
	}
	publicJWK := jwtinfra.PublicJWK(&privateKey.PublicKey)

	// ---------------------------
	// Repositories (in-memory)
	// ---------------------------
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

	// userRepo := memory.NewUserRepository([]*user.User{
	// 	{
	// 		ID:         "user-123",
	// 		Email:      "user@example.com",
	// 		IsVerified: true,
	// 	},
	// })

	userRepo := memory.NewUserRepository(nil)

	authCodeRepo := memory.NewAuthCodeRepository()
	tokenRepo := memory.NewTokenRepository()

	// ---------------------------
	// OIDC service
	// ---------------------------
	signer := jwtinfra.NewRSASigner(privateKey)

	oidcService := oidc.NewOIDCService(
		issuer,
		signer,
		time.Now,
	)

	// ---- Services ----
	oauthService := oauth.NewOAuthService(
		clientRepo,
		authCodeRepo,
		time.Now,
	)

	tokenService := oauth.NewTokenService(
		clientRepo,
		userRepo,
		authCodeRepo,
		tokenRepo,
		oidcService,
		time.Now,
	)

	challengeRepo := memory.NewChallengeRepo()
	loginTokenRepo := memory.NewLoginTokenRepo()
	loginTokenService := auth.NewLoginTokenService(loginTokenRepo, time.Now)
	loginService := auth.NewLoginService(
		userRepo,
		challengeRepo,
		loginTokenService,
	)

	registrationService := auth.NewRegistrationService(userRepo)
	registerHandler := handlers.NewRegisterHandler(registrationService)

	// ---------------------------
	// HTTP handlers
	// ---------------------------
	authorizeHandler := handlers.NewAuthorizeHandler(oauthService)
	tokenHandler := handlers.NewTokenHandler(tokenService)
	oidcHandler := handlers.NewOIDCHandler(issuer)
	jwksHandler := handlers.NewJWKSHandler(publicJWK)
	loginHandler := handlers.NewLoginHandler(loginService)

	// ---------------------------
	// Router
	// ---------------------------
	router := httpiface.NewRouter(
		authorizeHandler,
		tokenHandler,
		oidcHandler,
		jwksHandler,
		loginHandler,
		registerHandler,
	)

	// // 🔴 You MUST create a test user here
	// salt := make([]byte, 16)
	// rand.Read(salt)

	// verifier := helpers.DeriveVerifier("password123", salt)

	// userRepo.Save(&user.User{
	// 	ID:               "user-1",
	// 	Username:         "alice",
	// 	Salt:             salt,
	// 	PasswordVerifier: verifier,
	// })
	// u, _ := userRepo.FindByUsername("alice")
	// log.Printf("Created test user: %+v\n", u)

	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)
	log.Printf("Auth server running on %s", addr)

	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}
