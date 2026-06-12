package middleware_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/middleware"
)

// startJWKSServer spins up a test HTTP server that serves a JWKS from the given private key.
// The middleware expects the JWKS at /.well-known/jwks.json.
func startJWKSServer(t *testing.T, privKey *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	pubJWK, err := jwk.FromRaw(privKey.Public())
	require.NoError(t, err)
	require.NoError(t, pubJWK.Set(jwk.AlgorithmKey, jwa.RS256))
	require.NoError(t, pubJWK.Set(jwk.KeyIDKey, "test-kid-1"))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubJWK))

	jwksBytes, err := json.Marshal(set)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBytes)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// signToken creates a signed RS256 JWT for the given subject and TTL.
func signToken(t *testing.T, privKey *rsa.PrivateKey, subject string, ttl time.Duration) string {
	t.Helper()

	tok, err := jwt.NewBuilder().
		Subject(subject).
		Issuer("test-issuer").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(ttl)).
		Build()
	require.NoError(t, err)

	privJWK, err := jwk.FromRaw(privKey)
	require.NoError(t, err)
	require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.RS256))
	require.NoError(t, privJWK.Set(jwk.KeyIDKey, "test-kid-1"))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privJWK))
	require.NoError(t, err)
	return string(signed)
}

// protectedRouter wraps a single GET /me endpoint behind the JWT middleware.
func protectedRouter(mw *middleware.JWTMiddleware) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/me", mw.Handler(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"user_id": c.GetString(middleware.JWTUserIDKey)})
	})
	return r
}

func TestJWTMiddleware_ValidToken_SetsUserID(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := startJWKSServer(t, privKey)
	mw := middleware.NewJWTMiddleware(srv.URL)

	token := signToken(t, privKey, "user-abc", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	protectedRouter(mw).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "user-abc", body["user_id"])
}

func TestJWTMiddleware_MissingAuthHeader_Returns401(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := startJWKSServer(t, privKey)
	mw := middleware.NewJWTMiddleware(srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/me", nil) // no Authorization header
	w := httptest.NewRecorder()
	protectedRouter(mw).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, "UNAUTHENTICATED", body["code"])
}

func TestJWTMiddleware_NotBearerScheme_Returns401(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := startJWKSServer(t, privKey)
	mw := middleware.NewJWTMiddleware(srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	protectedRouter(mw).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTMiddleware_ExpiredToken_Returns401(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := startJWKSServer(t, privKey)
	mw := middleware.NewJWTMiddleware(srv.URL)

	// Token expired 5 minutes ago
	token := signToken(t, privKey, "user-abc", -5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	protectedRouter(mw).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTMiddleware_WrongSigningKey_Returns401(t *testing.T) {
	privKeyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privKeyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Middleware trusts key A's JWKS, but token is signed with key B
	srv := startJWKSServer(t, privKeyA)
	mw := middleware.NewJWTMiddleware(srv.URL)

	token := signToken(t, privKeyB, "user-abc", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	protectedRouter(mw).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTMiddleware_MalformedToken_Returns401(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := startJWKSServer(t, privKey)
	mw := middleware.NewJWTMiddleware(srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer not.a.real.jwt.token")
	w := httptest.NewRecorder()
	protectedRouter(mw).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
