package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/joho/godotenv"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/config"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/handler"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/repository"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/service"
	"github.com/rabbicse/go-projects/projects/url-shortner/pkg/middleware"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Load configuration
	cfg := config.LoadConfig()

	// Initialize repositories
	postgresRepo, err := repository.NewPostgresRepo(
		cfg.Postgres.Host,
		cfg.Postgres.Port,
		cfg.Postgres.User,
		cfg.Postgres.Password,
		cfg.Postgres.DBName,
		cfg.Postgres.SSLMode,
	)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer postgresRepo.Close()

	redisRepo, err := repository.NewRedisRepo(
		cfg.Redis.Host,
		cfg.Redis.Port,
	)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisRepo.Close()

	// Initialize service
	urlService := service.NewURLService(postgresRepo, redisRepo, cfg.Server.BaseURL, int64(cfg.Server.MachineID))

	// Initialize handler
	urlHandler := handler.NewURLHandler(urlService)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "URL Shortener",
	})

	// Middleware
	app.Use(logger.New())
	app.Use(middleware.RateLimiter())

	// Routes
	app.Post("/shorten", urlHandler.CreateShortURL)
	app.Get("/:code", urlHandler.Redirect)
	app.Get("/health", urlHandler.HealthCheck)

	// Start server
	port := cfg.Server.Port
	if port == "" {
		port = "3000"
	}

	log.Printf("Server starting on port %s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
