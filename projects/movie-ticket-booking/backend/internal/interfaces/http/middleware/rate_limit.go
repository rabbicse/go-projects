package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
)

type ipWindow struct {
	mu         sync.Mutex
	timestamps []time.Time
}

// HoldRateLimit returns a sliding-window per-IP rate limiter.
// Each call creates isolated state, so different routes get independent limits.
func HoldRateLimit(limit int, window time.Duration) gin.HandlerFunc {
	var windows sync.Map

	return func(c *gin.Context) {
		ip := c.ClientIP()
		val, _ := windows.LoadOrStore(ip, &ipWindow{})
		w := val.(*ipWindow)

		now := time.Now()
		cutoff := now.Add(-window)

		w.mu.Lock()
		// Drop timestamps outside the window.
		i := 0
		for i < len(w.timestamps) && w.timestamps[i].Before(cutoff) {
			i++
		}
		w.timestamps = w.timestamps[i:]

		if len(w.timestamps) >= limit {
			w.mu.Unlock()
			c.JSON(http.StatusTooManyRequests, apierr.New("RATE_LIMIT_EXCEEDED", "too many hold requests; please wait before trying again"))
			c.Abort()
			return
		}

		w.timestamps = append(w.timestamps, now)
		w.mu.Unlock()

		c.Next()
	}
}
