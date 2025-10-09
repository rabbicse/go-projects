package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"honnef.co/go/tools/config"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize logger
	logger.Init(cfg.LogLevel)

	// Initialize template engine
	engine := html.New("./web/templates", ".html")

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "MagicStream Server",
		Views:        engine,
		ErrorHandler: middleware.ErrorHandler,
	})

	// Global middleware
	app.Use(recover.New())
	app.Use(compress.New())
	app.Use(middleware.CORS())
	app.Use(middleware.Logger())

	// Serve static files
	app.Static("/static", "./static")
	app.Static("/uploads", "./static/uploads")

	// API routes
	api := app.Group("/api/v1")
	{
		media := api.Group("/media")
		media.Get("/", handlers.GetMediaList)
		media.Post("/upload", handlers.UploadMedia)
		media.Get("/:id", handlers.GetMediaInfo)
		media.Delete("/:id", handlers.DeleteMedia)

		stream := api.Group("/stream")
		stream.Get("/:id", handlers.StreamMedia)
		stream.Get("/:id/:filename", handlers.StreamMediaFile)
	}

	// WebSocket routes
	ws := app.Group("/ws")
	{
		ws.Get("/", handlers.WebSocketHandler)
	}

	// Web routes
	app.Get("/", handlers.IndexHandler)
	app.Get("/player/:id", handlers.PlayerHandler)

	// Start server
	log.Printf("MagicStream Server starting on %s", cfg.ServerAddress)
	log.Fatal(app.Listen(cfg.ServerAddress))
}
