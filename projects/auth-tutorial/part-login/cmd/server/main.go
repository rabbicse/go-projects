package main

import (
	"fmt"
	"log"

	"github.com/rabbicse/auth-service/internal/config"
	httpiface "github.com/rabbicse/auth-service/internal/interfaces/http"
)

func main() {
	// 1. Load configuration
	cfg := config.Load()

	// 2. Create HTTP router
	router := httpiface.NewRouter()

	// 3. Start server
	addr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)

	log.Printf("Auth server running on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}
