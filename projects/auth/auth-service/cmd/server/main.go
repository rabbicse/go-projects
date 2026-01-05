package main

import (
	"fmt"
	"log"
	"time"

	"github.com/rabbicse/auth-service/internal/application/oauth"
	"github.com/rabbicse/auth-service/internal/config"
	"github.com/rabbicse/auth-service/internal/domain/client"
	"github.com/rabbicse/auth-service/internal/infrastructure/persistence/memory"
	httpiface "github.com/rabbicse/auth-service/internal/interfaces/http"
	"github.com/rabbicse/auth-service/internal/interfaces/http/handlers"
)

func main() {
	// 1. Load configuration
	cfg := config.Load()

	// ---- Seed data (TEMP) ----
	clientRepo := memory.NewClientRepository([]*client.Client{
		{
			ID:           "client-123",
			SecretHash:   "secret",
			RedirectURIs: []string{"http://localhost:3000/callback"},
			Scopes:       []string{"openid", "profile", "email"},
			GrantTypes:   []client.GrantType{client.GrantAuthorizationCode},
			IsPublic:     false,
		},
	})

	authCodeRepo := memory.NewAuthCodeRepository()
	tokenRepo := memory.NewTokenRepository()

	// ---- Services ----
	oauthService := oauth.NewOAuthService(
		clientRepo,
		authCodeRepo,
		func() time.Time { return time.Now() },
	)

	tokenService := oauth.NewTokenService(
		clientRepo,
		authCodeRepo,
		tokenRepo,
		func() time.Time { return time.Now() },
	)

	// ---- Handlers ----
	authorizeHandler := handlers.NewAuthorizeHandler(oauthService)
	tokenHandler := handlers.NewTokenHandler(tokenService)

	// ---- HTTP ----
	router := httpiface.NewRouter(authorizeHandler, tokenHandler)

	// 3. Start server
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)

	log.Printf("Auth server running on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}
