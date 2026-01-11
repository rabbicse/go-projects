package middleware

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

type RateLimiter struct {
	cacheClient *redis.ClusterClient
}

func NewRateLimiter(redisClient *redis.ClusterClient) *RateLimiter {
	return &RateLimiter{cacheClient: redisClient}
}

func (rl *RateLimiter) RateLimit(requests int, duration time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		clientIP := c.IP()
		key := "rate_limit:" + clientIP

		// Use Redis for distributed rate limiting
		count, err := rl.cacheClient.Incr(c.Context(), key).Result()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Internal server error",
			})
		}

		if count == 1 {
			// Set expiration on first request
			rl.cacheClient.Expire(c.Context(), key, duration)
		}

		if count > int64(requests) {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":   "Rate limit exceeded",
				"message": "Too many requests, please try again later",
			})
		}

		// Set rate limit headers
		c.Set("X-RateLimit-Limit", strconv.Itoa(requests))
		c.Set("X-RateLimit-Remaining", strconv.Itoa(requests-int(count)))
		c.Set("X-RateLimit-Reset", time.Now().Add(duration).Format(time.RFC1123))

		return c.Next()
	}
}
