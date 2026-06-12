package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/middleware"
)

const testHS256Secret = "super-secret-for-unit-tests"

type testClaims struct {
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

// signHS256 creates a signed HS256 JWT for tests.
func signHS256(t *testing.T, subject string, roles []string, secret string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, testClaims{
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}).SignedString([]byte(secret))
	require.NoError(t, err)
	return tok
}

func requireAuthRouter(secret string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/me", middleware.RequireAuth(secret), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"user_id": c.GetString(middleware.JWTUserIDKey)})
	})
	return r
}

func requireRoleRouter(secret, role string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/admin", middleware.RequireAuth(secret), middleware.RequireRole(role), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

// ── RequireAuth ───────────────────────────────────────────────────────────────

func TestRequireAuth_ValidToken_SetsUserID(t *testing.T) {
	token := signHS256(t, "user-123", []string{"customer"}, testHS256Secret, 5*time.Minute)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	requireAuthRouter(testHS256Secret).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "user-123")
}

func TestRequireAuth_MissingHeader_Returns401(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	requireAuthRouter(testHS256Secret).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "UNAUTHENTICATED")
}

func TestRequireAuth_NotBearerScheme_Returns401(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	requireAuthRouter(testHS256Secret).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "UNAUTHENTICATED")
}

func TestRequireAuth_ExpiredToken_Returns401(t *testing.T) {
	token := signHS256(t, "user-123", nil, testHS256Secret, -5*time.Minute)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	requireAuthRouter(testHS256Secret).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "UNAUTHENTICATED")
}

func TestRequireAuth_WrongSigningKey_Returns401(t *testing.T) {
	token := signHS256(t, "user-123", nil, "different-secret", 5*time.Minute)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	requireAuthRouter(testHS256Secret).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_MalformedToken_Returns401(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer not.a.real.jwt")
	requireAuthRouter(testHS256Secret).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequireAuth_EmptyBearerValue_Returns401(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer ")
	requireAuthRouter(testHS256Secret).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── RequireRole ───────────────────────────────────────────────────────────────

func TestRequireRole_MatchingRole_Passes(t *testing.T) {
	token := signHS256(t, "admin-1", []string{"admin"}, testHS256Secret, 5*time.Minute)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	requireRoleRouter(testHS256Secret, "admin").ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireRole_WrongRole_Returns403(t *testing.T) {
	token := signHS256(t, "user-1", []string{"customer"}, testHS256Secret, 5*time.Minute)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	requireRoleRouter(testHS256Secret, "admin").ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "FORBIDDEN")
}

func TestRequireRole_NoRolesClaim_Returns403(t *testing.T) {
	token := signHS256(t, "user-1", nil, testHS256Secret, 5*time.Minute)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	requireRoleRouter(testHS256Secret, "admin").ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireRole_MultipleRoles_AdminIncluded_Passes(t *testing.T) {
	token := signHS256(t, "superuser-1", []string{"customer", "admin"}, testHS256Secret, 5*time.Minute)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	requireRoleRouter(testHS256Secret, "admin").ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
