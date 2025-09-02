package main

import (
	"context"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/monitor"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rabbicse/go-projects/project/url-shortner/api-gateway/internal/config"
	"github.com/rabbicse/go-projects/project/url-shortner/api-gateway/internal/middleware"
	loadbalancer "github.com/rabbicse/go-projects/project/url-shortner/api-gateway/internal/pkg/load_balancer"
	"github.com/redis/go-redis/v9"
)

type APIGateway struct {
	app          *fiber.App
	config       *config.Config
	redisClient  *redis.Client
	loadBalancer *loadbalancer.RoundRobinLoadBalancer
	rateLimiter  *middleware.RateLimiter
	cache        *middleware.CacheMiddleware
	auth         *middleware.AuthMiddleware
}

func NewAPIGateway(cfg *config.Config) *APIGateway {
	// Initialize Redis
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: "",
		DB:       0,
	})

	// Test Redis connection
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Initialize load balancer
	loadBalancer := loadbalancer.NewRoundRobinLoadBalancer(cfg.BackendServers)

	// Initialize middleware
	rateLimiter := middleware.NewRateLimiter(redisClient)
	cache := middleware.NewCacheMiddleware(redisClient)
	auth := middleware.NewAuthMiddleware(cfg.JWTSecret)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:               "URL Shortener API Gateway",
		Prefork:               false,
		CaseSensitive:         true,
		StrictRouting:         true,
		ServerHeader:          "Fiber",
		DisableStartupMessage: false,
	})

	return &APIGateway{
		app:          app,
		config:       cfg,
		redisClient:  redisClient,
		loadBalancer: loadBalancer,
		rateLimiter:  rateLimiter,
		cache:        cache,
		auth:         auth,
	}
}

func (ag *APIGateway) SetupMiddleware() {
	// Basic middleware
	ag.app.Use(recover.New())
	ag.app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Accept,Authorization",
	}))
	ag.app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
	}))
	ag.app.Use(logger.New(logger.Config{
		Format: "[${ip}]:${port} ${status} - ${method} ${path}\n",
	}))

	// Tracing
	if ag.config.EnableTracing {
		tp, err := middleware.SetupTracing("api-gateway", ag.config.JaegerEndpoint)
		if err != nil {
			log.Printf("Failed to setup tracing: %v", err)
		} else {
			defer tp.Shutdown(context.Background())
			ag.app.Use(middleware.TracingMiddleware())
		}
	}

	// Rate limiting
	ag.app.Use(ag.rateLimiter.RateLimit(ag.config.RateLimitRequests, ag.config.RateLimitDuration))

	// Authentication
	ag.app.Use(ag.auth.Authenticate())
}

func (ag *APIGateway) SetupRoutes() {
	// Health check endpoint
	ag.app.Get("/health", ag.healthCheck)

	// Metrics dashboard
	ag.app.Get("/metrics", monitor.New(monitor.Config{Title: "API Gateway Metrics"}))

	// API routes
	api := ag.app.Group("/api/v1")

	// Shorten URL (POST /api/v1/shorten)
	api.Post("/shorten", ag.proxyRequest)

	// Get URL stats (GET /api/v1/stats/:id)
	api.Get("/stats/:id", ag.cache.Cache(ag.config.CacheTTL), ag.proxyRequest)

	// Redirect (GET /:id)
	ag.app.Get("/:id", ag.cache.Cache(5*time.Minute), ag.proxyRequest)
}

func (ag *APIGateway) healthCheck(c *fiber.Ctx) error {
	// Check Redis connection
	if err := ag.redisClient.Ping(c.Context()).Err(); err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status":  "unhealthy",
			"redis":   "disconnected",
			"message": "Redis connection failed",
		})
	}

	// Check backend services
	serverStatus := ag.loadBalancer.GetServerStatus()
	healthyCount := 0
	for _, healthy := range serverStatus {
		if healthy {
			healthyCount++
		}
	}

	return c.JSON(fiber.Map{
		"status":          "healthy",
		"redis":           "connected",
		"backend_servers": len(ag.config.BackendServers),
		"healthy_servers": healthyCount,
		"server_status":   serverStatus,
		"timestamp":       time.Now().UTC(),
	})
}

func (ag *APIGateway) proxyRequest(c *fiber.Ctx) error {
	// Get next healthy backend server
	backendURL, err := ag.loadBalancer.GetNextServer()
	if err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error":   "Service unavailable" + err.Error(),
			"message": "No healthy backend servers available",
		})
	}

	// Create proxy request
	targetURL := "http://" + backendURL + c.OriginalURL()

	// Forward the request
	statusCode, body, err := ag.doProxyRequest(c, targetURL)
	if err != nil {
		// Mark server as unhealthy
		ag.loadBalancer.SetServerHealth(backendURL, false)
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
			"error":   "Bad gateway " + err.Error(),
			"message": "Failed to connect to backend service",
		})
	}

	// Mark server as healthy
	ag.loadBalancer.SetServerHealth(backendURL, true)

	// Return response
	c.Status(statusCode)
	return c.Send(body)
}

func (ag *APIGateway) doProxyRequest(c *fiber.Ctx, targetURL string) (int, []byte, error) {
	// Implement actual HTTP request forwarding
	// This is a simplified version - in production, use proper HTTP client
	// with timeouts and connection pooling

	// For now, we'll use Fiber's built-in client
	agent := fiber.AcquireAgent()
	defer fiber.ReleaseAgent(agent)

	req := agent.Request()
	req.Header.SetMethod(c.Method())
	req.SetRequestURI(targetURL)

	// Copy headers
	c.Request().Header.VisitAll(func(key, value []byte) {
		req.Header.SetBytesKV(key, value)
	})

	// Copy body
	if c.Request().Body() != nil {
		req.SetBody(c.Request().Body())
	}

	if err := agent.Parse(); err != nil {
		return 0, nil, err
	}

	code, body, errs := agent.Bytes()
	if len(errs) > 0 {
		return 0, nil, errs[0]
	}

	return code, body, nil
}

func (ag *APIGateway) StartHealthChecks() {
	ticker := time.NewTicker(ag.config.HealthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		for _, serverURL := range ag.config.BackendServers {
			go ag.checkServerHealth(serverURL)
		}
	}
}

func (ag *APIGateway) checkServerHealth(serverURL string) {
	_, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Simple health check
	healthy := true
	// Implement actual health check logic here

	ag.loadBalancer.SetServerHealth(serverURL, healthy)
}

func (ag *APIGateway) Start() error {
	ag.SetupMiddleware()
	ag.SetupRoutes()

	// Start health checks in background
	go ag.StartHealthChecks()

	log.Printf("API Gateway starting on port %s", ag.config.Port)
	return ag.app.Listen(":" + ag.config.Port)
}

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Create and start API Gateway
	gateway := NewAPIGateway(cfg)
	if err := gateway.Start(); err != nil {
		log.Fatalf("Failed to start API Gateway: %v", err)
	}
}
