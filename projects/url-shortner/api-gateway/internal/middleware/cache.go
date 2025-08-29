package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

type CacheMiddleware struct {
	redisClient *redis.Client
}

func NewCacheMiddleware(redisClient *redis.Client) *CacheMiddleware {
	return &CacheMiddleware{redisClient: redisClient}
}

func (cm *CacheMiddleware) Cache(ttl time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Only cache GET requests
		if c.Method() != "GET" {
			return c.Next()
		}

		cacheKey := "cache:" + c.OriginalURL()

		// Try to get from cache
		cached, err := cm.redisClient.Get(c.Context(), cacheKey).Result()
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
			cm.redisClient.Set(c.Context(), cacheKey, responseBody, ttl)
		}

		return nil
	}
}
