package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
)

// JWTUserRolesKey is the gin context key for the slice of roles set by RequireAuth.
const JWTUserRolesKey = "user_roles"

// localClaims is the minimal JWT payload shape validated by RequireAuth.
// It mirrors authapp.Claims but lives here to avoid an interfaces→application import.
type localClaims struct {
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

// RequireAuth returns a Gin middleware that validates HS256 Bearer tokens signed
// with jwtSecret. On success it sets JWTUserIDKey (sub) and JWTUserRolesKey
// ([]string) in the request context. Aborts with 401 on any failure.
//
// Extension point: swap HS256 for RS256/ECDSA by changing the keyfunc here;
// the rest of the codebase (handlers, RequireRole) is unaffected.
func RequireAuth(jwtSecret string) gin.HandlerFunc {
	key := []byte(jwtSecret)
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				apierr.New("UNAUTHENTICATED", "authorization token required"))
			return
		}
		raw := strings.TrimPrefix(auth, "Bearer ")

		claims := &localClaims{}
		_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return key, nil
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				apierr.New("UNAUTHENTICATED", "invalid or expired token"))
			return
		}

		c.Set(JWTUserIDKey, claims.Subject)
		c.Set(JWTUserRolesKey, claims.Roles)
		c.Next()
	}
}

// RequireRole returns a Gin middleware that enforces role membership.
// Must be chained after RequireAuth (reads JWTUserRolesKey from context).
// Future roles only require adding a new RoleType constant — no middleware changes.
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		rolesVal, _ := c.Get(JWTUserRolesKey)
		roles, _ := rolesVal.([]string)
		for _, r := range roles {
			if r == role {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden,
			apierr.New("FORBIDDEN", "you do not have permission to perform this action"))
	}
}
