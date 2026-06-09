package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BodyLimit wraps the request body with an io.LimitedReader to prevent
// memory exhaustion from abnormally large payloads (SEC-09).
func BodyLimit(limitBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limitBytes)
		c.Next()
	}
}
