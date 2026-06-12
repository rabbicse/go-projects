package integration_test

// TestBookingFlow_WithJWT exercises the full HTTP stack end-to-end:
//
//   RSA key pair → JWKS httptest server → JWTMiddleware → Gin router
//   Redis container (seat locks) + MongoDB container (bookings)
//
// Run: make test-integration   (requires Docker)

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bookingsvc "github.com/rabbicse/movie-ticket-booking/internal/application/booking"
	apievents "github.com/rabbicse/movie-ticket-booking/internal/application/events"
	moviesvc "github.com/rabbicse/movie-ticket-booking/internal/application/movie"
	paymentsvc "github.com/rabbicse/movie-ticket-booking/internal/application/payment"
	"github.com/rabbicse/movie-ticket-booking/internal/infrastructure/gateway"
	bookingdomain "github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	moviedomain "github.com/rabbicse/movie-ticket-booking/internal/domain/movie"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
	mongoinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/mongodb"
	redisinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/redis"
	ginhttp "github.com/rabbicse/movie-ticket-booking/internal/interfaces/http"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/middleware"
)

// buildTestJWKSServer starts an httptest server that serves a JWKS derived from privKey.
func buildTestJWKSServer(t *testing.T, privKey *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	pubJWK, err := jwk.FromRaw(privKey.Public())
	require.NoError(t, err)
	require.NoError(t, pubJWK.Set(jwk.AlgorithmKey, jwa.RS256))
	require.NoError(t, pubJWK.Set(jwk.KeyIDKey, "integration-kid"))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubJWK))

	b, err := json.Marshal(set)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// makeTestToken signs an RS256 JWT for subject valid for ttl.
func makeTestToken(t *testing.T, privKey *rsa.PrivateKey, subject string, ttl time.Duration) string {
	t.Helper()

	tok, err := jwt.NewBuilder().
		Subject(subject).
		Issuer("integration-test").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(ttl)).
		Build()
	require.NoError(t, err)

	privJWK, err := jwk.FromRaw(privKey)
	require.NoError(t, err)
	require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.RS256))
	require.NoError(t, privJWK.Set(jwk.KeyIDKey, "integration-kid"))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privJWK))
	require.NoError(t, err)
	return string(signed)
}

func TestBookingFlow_WithJWT(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping JWT booking integration test in short mode")
	}

	ctx := context.Background()

	// ── Infrastructure ────────────────────────────────────────────────────────
	rdb := startRedis(t)
	db := startMongoDB(t)

	movieRepo := mongoinfra.NewMovieRepository(db)
	bookingRepo := mongoinfra.NewBookingRepository(db)
	seatLockRepo := redisinfra.NewSeatLockRepository(rdb)

	require.NoError(t, movieRepo.EnsureIndexes(ctx))
	require.NoError(t, bookingRepo.EnsureIndexes(ctx))

	// ── Seed a movie + showtime directly ─────────────────────────────────────
	movieSvc := moviesvc.NewService(movieRepo)
	require.NoError(t, movieSvc.CreateMovie(ctx, moviedomain.Movie{
		ID:          "test-movie-1",
		Title:       "Integration Test Film",
		Genre:       []string{"Action"},
		Rating:      8.0,
		DurationMin: 120,
	}))
	require.NoError(t, movieSvc.CreateShowtime(ctx, moviedomain.Showtime{
		ID:          "test-show-1",
		MovieID:     "test-movie-1",
		Hall:        "Hall A",
		StartTime:   time.Now().Add(2 * time.Hour),
		EndTime:     time.Now().Add(4 * time.Hour),
		Rows:        8,
		SeatsPerRow: 10,
		Price:       shared.USD(1500),
	}))

	// ── Application services ──────────────────────────────────────────────────
	dispatcher := apievents.NewInProcess()
	dispatcher.Register(bookingdomain.EventNameBookingCreated, apievents.LogHandler())
	dispatcher.Register(bookingdomain.EventNameBookingConfirmed, apievents.LogHandler())

	bookSvc := bookingsvc.NewService(
		seatLockRepo, bookingRepo, movieRepo,
		dispatcher, 4, 10*time.Minute,
	)

	// ── RSA keys + JWKS server ────────────────────────────────────────────────
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwksSrv := buildTestJWKSServer(t, privKey)
	jwtMW := middleware.NewJWTMiddleware(jwksSrv.URL)

	// ── Full router with JWT auth enabled ─────────────────────────────────────
	paySvc := paymentsvc.NewService(gateway.NewMockPaymentGateway(), bookSvc)
	router := ginhttp.NewRouter(movieSvc, bookSvc, paySvc, nil, nil, nil, ginhttp.RouterConfig{
		AllowedOrigins: []string{"*"},
		MaxSeats:       4,
		AdminUser:      "admin",
		AdminPassword:  "admin",
		JWTAuth:        jwtMW.Handler(),
	})

	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)

	token := makeTestToken(t, privKey, "integration-user-1", 5*time.Minute)
	client := ts.Client()

	// ── 1. Hold seats ─────────────────────────────────────────────────────────
	holdBody, _ := json.Marshal(map[string]any{"seat_ids": []string{"A1", "A2"}})
	holdReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/showtimes/test-show-1/hold", bytes.NewReader(holdBody))
	holdReq.Header.Set("Content-Type", "application/json")
	holdReq.Header.Set("Authorization", "Bearer "+token)

	holdResp, err := client.Do(holdReq)
	require.NoError(t, err)
	defer holdResp.Body.Close()
	assert.Equal(t, http.StatusCreated, holdResp.StatusCode)

	var holdData map[string]any
	require.NoError(t, json.NewDecoder(holdResp.Body).Decode(&holdData))
	sessionID, ok := holdData["session_id"].(string)
	require.True(t, ok, "session_id missing from hold response")
	assert.Equal(t, "held", holdData["status"])
	assert.Equal(t, "integration-user-1", holdData["user_id"])

	// ── 2. Confirm booking (no user_id in body — JWT provides it) ─────────────
	confirmBody, _ := json.Marshal(map[string]any{})
	confirmReq, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		ts.URL+"/api/v1/sessions/"+sessionID+"/confirm", bytes.NewReader(confirmBody))
	confirmReq.Header.Set("Content-Type", "application/json")
	confirmReq.Header.Set("Authorization", "Bearer "+token)

	confirmResp, err := client.Do(confirmReq)
	require.NoError(t, err)
	defer confirmResp.Body.Close()
	assert.Equal(t, http.StatusOK, confirmResp.StatusCode)

	var confirmData map[string]any
	require.NoError(t, json.NewDecoder(confirmResp.Body).Decode(&confirmData))
	assert.Equal(t, "confirmed", confirmData["status"])
	assert.Equal(t, "integration-user-1", confirmData["user_id"])

	// ── 3. Request without token is rejected ──────────────────────────────────
	noAuthReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/showtimes/test-show-1/hold", bytes.NewReader(holdBody))
	noAuthReq.Header.Set("Content-Type", "application/json")
	// No Authorization header

	noAuthResp, err := client.Do(noAuthReq)
	require.NoError(t, err)
	defer noAuthResp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, noAuthResp.StatusCode)
}
