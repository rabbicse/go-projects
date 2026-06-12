package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	authapp "github.com/rabbicse/movie-ticket-booking/internal/application/auth"
	apievents "github.com/rabbicse/movie-ticket-booking/internal/application/events"
	bookingsvc "github.com/rabbicse/movie-ticket-booking/internal/application/booking"
	moviesvc "github.com/rabbicse/movie-ticket-booking/internal/application/movie"
	paymentsvc "github.com/rabbicse/movie-ticket-booking/internal/application/payment"
	bookingdomain "github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/infrastructure/gateway"
	mongoinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/mongodb"
	redisinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/redis"
	ginhttp "github.com/rabbicse/movie-ticket-booking/internal/interfaces/http"
)

const testJWTSecret = "integration-test-jwt-secret-32chars!!"

// buildAuthRouter wires the full HTTP stack with HS256 auth enabled.
func buildAuthRouter(t *testing.T) *ginhttp.RouterConfig {
	t.Helper()
	return &ginhttp.RouterConfig{
		AllowedOrigins: []string{"*"},
		MaxSeats:       4,
		AdminUser:      "admin",
		AdminPassword:  "admin",
		JWTSecret:      testJWTSecret,
	}
}

func buildFullRouter(t *testing.T) http.Handler {
	t.Helper()
	ctx := context.Background()

	rdb := startRedis(t)
	db := startMongoDB(t)

	movieRepo := mongoinfra.NewMovieRepository(db)
	bookingRepo := mongoinfra.NewBookingRepository(db)
	userRepo := mongoinfra.NewUserRepository(db)
	seatLockRepo := redisinfra.NewSeatLockRepository(rdb)
	refreshStore := redisinfra.NewRefreshTokenStore(rdb)

	require.NoError(t, movieRepo.EnsureIndexes(ctx))
	require.NoError(t, bookingRepo.EnsureIndexes(ctx))
	require.NoError(t, userRepo.EnsureIndexes(ctx))

	dispatcher := apievents.NewInProcess()
	dispatcher.Register(bookingdomain.EventNameBookingCreated, apievents.LogHandler())
	dispatcher.Register(bookingdomain.EventNameBookingConfirmed, apievents.LogHandler())

	movieSvc := moviesvc.NewService(movieRepo)
	bookSvc := bookingsvc.NewService(seatLockRepo, bookingRepo, movieRepo, dispatcher, 4, 10*time.Minute)
	paySvc := paymentsvc.NewService(gateway.NewMockPaymentGateway(), bookSvc)
	authSvc := authapp.NewService(userRepo, refreshStore, testJWTSecret, 7*24*time.Hour)

	return ginhttp.NewRouter(movieSvc, bookSvc, paySvc, authSvc, nil, nil, ginhttp.RouterConfig{
		AllowedOrigins: []string{"*"},
		MaxSeats:       4,
		AdminUser:      "admin",
		AdminPassword:  "admin",
		JWTSecret:      testJWTSecret,
	})
}

func authJSON(t *testing.T, body any) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return bytes.NewBuffer(b)
}

// ── Register ──────────────────────────────────────────────────────────────────

func TestAuthFlow_Register_Returns201(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	router := buildFullRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", authJSON(t, map[string]any{
		"email":      "alice@example.com",
		"password":   "Secret1234!",
		"first_name": "Alice",
		"last_name":  "Smith",
	}))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotNil(t, resp["user"])
	assert.NotNil(t, resp["tokens"])
	tokens := resp["tokens"].(map[string]any)
	assert.NotEmpty(t, tokens["access_token"])
	assert.NotEmpty(t, tokens["refresh_token"])
}

func TestAuthFlow_Register_DuplicateEmail_Returns409(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	router := buildFullRouter(t)

	registerBody := authJSON(t, map[string]any{
		"email": "bob@example.com", "password": "Secret1234!",
		"first_name": "Bob", "last_name": "Jones",
	})
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", registerBody)
	req1.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w1, req1)
	require.Equal(t, http.StatusCreated, w1.Code)

	// Second registration with the same email.
	registerBody2 := authJSON(t, map[string]any{
		"email": "bob@example.com", "password": "DifferentPass1!",
		"first_name": "Bob2", "last_name": "Jones2",
	})
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", registerBody2)
	req2.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusConflict, w2.Code)
}

func TestAuthFlow_Register_MissingEmail_Returns400(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	router := buildFullRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", authJSON(t, map[string]any{
		"password": "Secret1234!",
	}))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Login ─────────────────────────────────────────────────────────────────────

func TestAuthFlow_Login_ValidCredentials_Returns200WithTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	router := buildFullRouter(t)

	// Register first.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", authJSON(t, map[string]any{
		"email": "carol@example.com", "password": "Secret1234!",
		"first_name": "Carol", "last_name": "White",
	}))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	// Now login.
	wl := httptest.NewRecorder()
	reql := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", authJSON(t, map[string]any{
		"email": "carol@example.com", "password": "Secret1234!",
	}))
	reql.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wl, reql)

	assert.Equal(t, http.StatusOK, wl.Code)
	var tokens map[string]any
	require.NoError(t, json.Unmarshal(wl.Body.Bytes(), &tokens))
	assert.NotEmpty(t, tokens["access_token"])
	assert.NotEmpty(t, tokens["refresh_token"])
}

func TestAuthFlow_Login_WrongPassword_Returns401(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	router := buildFullRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", authJSON(t, map[string]any{
		"email": "dave@example.com", "password": "Secret1234!",
		"first_name": "Dave", "last_name": "Black",
	}))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	wl := httptest.NewRecorder()
	reql := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", authJSON(t, map[string]any{
		"email": "dave@example.com", "password": "WrongPass!",
	}))
	reql.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wl, reql)

	assert.Equal(t, http.StatusUnauthorized, wl.Code)
}

// ── GetProfile ────────────────────────────────────────────────────────────────

func TestAuthFlow_GetProfile_WithValidToken_Returns200(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	router := buildFullRouter(t)

	// Register to get a token.
	wr := httptest.NewRecorder()
	reqr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", authJSON(t, map[string]any{
		"email": "eve@example.com", "password": "Secret1234!",
		"first_name": "Eve", "last_name": "Green",
	}))
	reqr.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wr, reqr)
	require.Equal(t, http.StatusCreated, wr.Code)

	var regResp map[string]any
	require.NoError(t, json.Unmarshal(wr.Body.Bytes(), &regResp))
	accessToken := regResp["tokens"].(map[string]any)["access_token"].(string)

	// Get profile with valid token.
	wp := httptest.NewRecorder()
	reqp := httptest.NewRequest(http.MethodGet, "/api/v1/auth/profile", nil)
	reqp.Header.Set("Authorization", "Bearer "+accessToken)
	router.ServeHTTP(wp, reqp)

	assert.Equal(t, http.StatusOK, wp.Code)
	var profile map[string]any
	require.NoError(t, json.Unmarshal(wp.Body.Bytes(), &profile))
	assert.Equal(t, "eve@example.com", profile["email"])
	assert.Equal(t, "Eve", profile["first_name"])
}

func TestAuthFlow_GetProfile_NoToken_Returns401(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	router := buildFullRouter(t)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/profile", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── RefreshTokens ─────────────────────────────────────────────────────────────

func TestAuthFlow_RefreshTokens_Returns200WithNewTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	router := buildFullRouter(t)

	// Register to get tokens.
	wr := httptest.NewRecorder()
	reqr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", authJSON(t, map[string]any{
		"email": "frank@example.com", "password": "Secret1234!",
		"first_name": "Frank", "last_name": "Blue",
	}))
	reqr.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wr, reqr)
	require.Equal(t, http.StatusCreated, wr.Code)

	var regResp map[string]any
	require.NoError(t, json.Unmarshal(wr.Body.Bytes(), &regResp))
	oldRefreshToken := regResp["tokens"].(map[string]any)["refresh_token"].(string)
	oldAccessToken := regResp["tokens"].(map[string]any)["access_token"].(string)

	// Refresh.
	wrf := httptest.NewRecorder()
	reqrf := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", authJSON(t, map[string]any{
		"refresh_token": oldRefreshToken,
	}))
	reqrf.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wrf, reqrf)

	assert.Equal(t, http.StatusOK, wrf.Code)
	var newTokens map[string]any
	require.NoError(t, json.Unmarshal(wrf.Body.Bytes(), &newTokens))
	assert.NotEmpty(t, newTokens["access_token"])
	assert.NotEmpty(t, newTokens["refresh_token"])
	// New tokens must differ from old ones.
	assert.NotEqual(t, oldAccessToken, newTokens["access_token"])
	assert.NotEqual(t, oldRefreshToken, newTokens["refresh_token"])
}

// ── Logout ────────────────────────────────────────────────────────────────────

func TestAuthFlow_Logout_Returns204(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	router := buildFullRouter(t)

	// Register.
	wr := httptest.NewRecorder()
	reqr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", authJSON(t, map[string]any{
		"email": "grace@example.com", "password": "Secret1234!",
		"first_name": "Grace", "last_name": "Red",
	}))
	reqr.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wr, reqr)
	require.Equal(t, http.StatusCreated, wr.Code)

	var regResp map[string]any
	require.NoError(t, json.Unmarshal(wr.Body.Bytes(), &regResp))
	refreshToken := regResp["tokens"].(map[string]any)["refresh_token"].(string)

	// Logout.
	wl := httptest.NewRecorder()
	reql := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", authJSON(t, map[string]any{
		"refresh_token": refreshToken,
	}))
	reql.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wl, reql)

	assert.Equal(t, http.StatusNoContent, wl.Code)
}

func TestAuthFlow_Logout_AfterLogout_RefreshInvalidated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	router := buildFullRouter(t)

	// Register.
	wr := httptest.NewRecorder()
	reqr := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", authJSON(t, map[string]any{
		"email": "hank@example.com", "password": "Secret1234!",
		"first_name": "Hank", "last_name": "Violet",
	}))
	reqr.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wr, reqr)
	require.Equal(t, http.StatusCreated, wr.Code)

	var regResp map[string]any
	require.NoError(t, json.Unmarshal(wr.Body.Bytes(), &regResp))
	refreshToken := regResp["tokens"].(map[string]any)["refresh_token"].(string)

	// Logout.
	wl := httptest.NewRecorder()
	reql := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", authJSON(t, map[string]any{
		"refresh_token": refreshToken,
	}))
	reql.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wl, reql)
	require.Equal(t, http.StatusNoContent, wl.Code)

	// Using the same refresh token after logout must fail.
	wrf := httptest.NewRecorder()
	reqrf := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", authJSON(t, map[string]any{
		"refresh_token": refreshToken,
	}))
	reqrf.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(wrf, reqrf)

	assert.Equal(t, http.StatusUnauthorized, wrf.Code, "refresh token must be invalidated after logout")
}
