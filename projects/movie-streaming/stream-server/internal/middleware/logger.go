package middleware

import (
	"magicstream/pkg/logger"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Logger middleware
func Logger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Process request
		err := c.Next()

		// Log request details
		logger.Info().
			Str("method", c.Method()).
			Str("path", c.Path()).
			Int("status", c.Response().StatusCode()).
			Str("ip", c.IP()).
			Dur("latency", time.Since(start)).
			Msg("HTTP request")

		return err
	}
}
