package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/joho/godotenv"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/handler"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/infra/idgenerator"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/repository"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/service"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/config"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/pkg/middleware"
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

	// Initialize id generator
	idGenerator := idgenerator.NewUniqueIDGenerator(int64(cfg.Server.MachineID), 16, redisRepo)

	// Initialize shortner service
	// postgresRepo, redisRepo, cfg.Server.BaseURL, int64(cfg.Server.MachineID)

	shortenService := service.NewShortenerService(&service.ShortnerServiceConfig{
		PostgresRepo: postgresRepo,
		RedisRepo:    redisRepo,
		BaseURL:      cfg.Server.BaseURL,
		Generator:    idGenerator,
	})

	redirectService := service.NewRedirectService(postgresRepo, redisRepo)

	// Initialize handlers
	shortenerHandler := handler.NewShortenHandler(shortenService)
	redirectHandler := handler.NewRedirectHandler(redirectService)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "URL Shortener",
	})

	// Middleware
	app.Use(logger.New())
	app.Use(middleware.RateLimiter())

	// Routes
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(http.StatusOK).JSON(fiber.Map{
			"status":    "healthy",
			"service":   "url-shortener",
			"timestamp": time.Now().Unix(),
		})
	})

	// business
	app.Post("/shorten", shortenerHandler.CreateShortURL)
	// app.Get("/health", urlHandler.HealthCheck)
	// Add health check endpoint
	app.Get("/:code", redirectHandler.Redirect)

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
