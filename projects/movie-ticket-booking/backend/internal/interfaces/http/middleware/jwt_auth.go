package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
)

// JWTUserIDKey is the gin context key set by JWTMiddleware.Handler().
const JWTUserIDKey = "user_id"

type JWTMiddleware struct {
	cache   *jwk.Cache
	jwksURL string
}

// NewJWTMiddleware creates a middleware that validates RS256 Bearer tokens against
// the JWKS published by the given base URL (base + "/.well-known/jwks.json").
func NewJWTMiddleware(jwksBaseURL string) *JWTMiddleware {
	jwksURL := strings.TrimRight(jwksBaseURL, "/") + "/.well-known/jwks.json"
	cache := jwk.NewCache(context.Background())
	cache.Register(jwksURL, jwk.WithMinRefreshInterval(15*time.Minute))
	// Pre-warm the cache; ignore errors — will retry on first request.
	_, _ = cache.Refresh(context.Background(), jwksURL)
	return &JWTMiddleware{cache: cache, jwksURL: jwksURL}
}

// Handler returns a Gin middleware that validates Bearer JWTs and sets "user_id"
// in the context (token.Subject). Aborts with 401 on any failure.
func (m *JWTMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				apierr.New("UNAUTHENTICATED", "authorization token required"))
			return
		}
		rawToken := strings.TrimPrefix(auth, "Bearer ")

		keySet, err := m.cache.Get(context.Background(), m.jwksURL)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				apierr.New("UNAUTHENTICATED", "auth service unavailable"))
			return
		}

		token, err := jwt.Parse(
			[]byte(rawToken),
			jwt.WithKeySet(keySet),
			jwt.WithValidate(true),
		)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				apierr.New("UNAUTHENTICATED", "invalid or expired token"))
			return
		}

		c.Set(JWTUserIDKey, token.Subject())
		c.Next()
	}
}
