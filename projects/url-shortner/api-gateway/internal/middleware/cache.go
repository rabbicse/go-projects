package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

type CacheMiddleware struct {
	cacheClient *redis.ClusterClient
}

func NewCacheMiddleware(cacheClient *redis.ClusterClient) *CacheMiddleware {
	return &CacheMiddleware{cacheClient: cacheClient}
}

func (cm *CacheMiddleware) Cache(ttl time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Only cache GET requests
		if c.Method() != "GET" {
			return c.Next()
		}

		cacheKey := "cache:" + c.OriginalURL()

		// Try to get from cache
		cached, err := cm.cacheClient.Get(c.Context(), cacheKey).Result()
		if err == nil {
			// Cache hit
			c.Set("X-Cache", "HIT")
			return c.SendString(cached)
		}

		// Cache miss, proceed with request
		c.Set("X-Cache", "MISS")

		// Capture response
		err = c.Next()
		if err != nil {
			return err
		}

		// Cache successful responses
		if c.Response().StatusCode() == fiber.StatusOK {
			responseBody := c.Response().Body()
			cm.cacheClient.Set(c.Context(), cacheKey, responseBody, ttl)
		}

		return nil
	}
}
