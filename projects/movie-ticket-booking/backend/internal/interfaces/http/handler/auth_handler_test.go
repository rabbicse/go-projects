package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	authapp "github.com/rabbicse/movie-ticket-booking/internal/application/auth"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/handler"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/middleware"
)

// mockAuthSvc implements handler.AuthService for unit tests.
type mockAuthSvc struct{ mock.Mock }

func (m *mockAuthSvc) Register(ctx context.Context, in authapp.RegisterInput) (*user.User, *authapp.TokenPair, error) {
	args := m.Called(ctx, in)
	u, _ := args.Get(0).(*user.User)
	tp, _ := args.Get(1).(*authapp.TokenPair)
	return u, tp, args.Error(2)
}
func (m *mockAuthSvc) Login(ctx context.Context, email, password string) (*authapp.TokenPair, error) {
	args := m.Called(ctx, email, password)
	tp, _ := args.Get(0).(*authapp.TokenPair)
	return tp, args.Error(1)
}
func (m *mockAuthSvc) RefreshTokens(ctx context.Context, refreshToken string) (*authapp.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	tp, _ := args.Get(0).(*authapp.TokenPair)
	return tp, args.Error(1)
}
func (m *mockAuthSvc) Logout(ctx context.Context, refreshToken string) error {
	return m.Called(ctx, refreshToken).Error(0)
}
func (m *mockAuthSvc) GetProfile(ctx context.Context, userID string) (*user.User, error) {
	args := m.Called(ctx, userID)
	u, _ := args.Get(0).(*user.User)
	return u, args.Error(1)
}

func authRouter(svc handler.AuthService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := handler.NewAuthHandler(svc)
	r.POST("/auth/register", h.Register)
	r.POST("/auth/login", h.Login)
	r.POST("/auth/refresh", h.Refresh)
	r.POST("/auth/logout", h.Logout)
	r.GET("/auth/profile", func(c *gin.Context) {
		c.Set(middleware.JWTUserIDKey, "u-1")
		h.GetProfile(c)
	})
	r.GET("/auth/profile/unauth", h.GetProfile) // no user_id set
	return r
}

func sampleTokenPair() *authapp.TokenPair {
	return &authapp.TokenPair{
		AccessToken:  "header.payload.sig",
		RefreshToken: "opaque-refresh-token",
		ExpiresIn:    900,
	}
}

func sampleAuthUser() *user.User {
	return &user.User{
		ID:        "u-1",
		Email:     "alice@example.com",
		FirstName: "Alice",
		LastName:  "Smith",
		Roles:     []user.RoleType{user.RoleCustomer},
	}
}

// ── POST /auth/register ───────────────────────────────────────────────────────

func TestAuthRegister_Success_Returns201(t *testing.T) {
	svc := &mockAuthSvc{}
	svc.On("Register", mock.Anything, authapp.RegisterInput{
		Email: "alice@example.com", Password: "s3cr3t99!", FirstName: "Alice", LastName: "Smith",
	}).Return(sampleAuthUser(), sampleTokenPair(), nil)

	body := jsonBody(t, map[string]any{
		"email": "alice@example.com", "password": "s3cr3t99!",
		"first_name": "Alice", "last_name": "Smith",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	authRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotNil(t, resp["user"])
	assert.NotNil(t, resp["tokens"])
	svc.AssertExpectations(t)
}

func TestAuthRegister_DuplicateEmail_Returns409(t *testing.T) {
	svc := &mockAuthSvc{}
	svc.On("Register", mock.Anything, mock.Anything).Return(nil, nil, user.ErrEmailTaken)

	body := jsonBody(t, map[string]any{
		"email": "taken@example.com", "password": "pass1234", "first_name": "Bob",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	req.Header.Set("Content-Type", "application/json")
	authRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "EMAIL_TAKEN", resp["code"])
}

func TestAuthRegister_MissingRequiredFields_Returns400(t *testing.T) {
	// No first_name → binding validation fails before service is called.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/register",
		jsonBody(t, map[string]any{"email": "a@b.com", "password": "pass1234"}))
	req.Header.Set("Content-Type", "application/json")
	authRouter(&mockAuthSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthRegister_InvalidEmail_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/register",
		jsonBody(t, map[string]any{
			"email": "not-an-email", "password": "pass1234", "first_name": "Bob",
		}))
	req.Header.Set("Content-Type", "application/json")
	authRouter(&mockAuthSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthRegister_PasswordTooShort_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/register",
		jsonBody(t, map[string]any{
			"email": "a@b.com", "password": "short", "first_name": "Bob",
		}))
	req.Header.Set("Content-Type", "application/json")
	authRouter(&mockAuthSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── POST /auth/login ──────────────────────────────────────────────────────────

func TestAuthLogin_Success_Returns200WithTokens(t *testing.T) {
	svc := &mockAuthSvc{}
	svc.On("Login", mock.Anything, "alice@example.com", "mypassword").
		Return(sampleTokenPair(), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		jsonBody(t, map[string]any{"email": "alice@example.com", "password": "mypassword"}))
	req.Header.Set("Content-Type", "application/json")
	authRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["access_token"])
	assert.NotEmpty(t, resp["refresh_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
	svc.AssertExpectations(t)
}

func TestAuthLogin_InvalidCredentials_Returns401(t *testing.T) {
	svc := &mockAuthSvc{}
	svc.On("Login", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, user.ErrInvalidPassword)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		jsonBody(t, map[string]any{"email": "a@b.com", "password": "wrong"}))
	req.Header.Set("Content-Type", "application/json")
	authRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "INVALID_CREDENTIALS", resp["code"])
}

func TestAuthLogin_MissingBody_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		bytes.NewBufferString(""))
	req.Header.Set("Content-Type", "application/json")
	authRouter(&mockAuthSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── POST /auth/refresh ────────────────────────────────────────────────────────

func TestAuthRefresh_ValidToken_Returns200NewPair(t *testing.T) {
	svc := &mockAuthSvc{}
	svc.On("RefreshTokens", mock.Anything, "old-refresh").
		Return(sampleTokenPair(), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh",
		jsonBody(t, map[string]any{"refresh_token": "old-refresh"}))
	req.Header.Set("Content-Type", "application/json")
	authRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["access_token"])
}

func TestAuthRefresh_InvalidToken_Returns401(t *testing.T) {
	svc := &mockAuthSvc{}
	svc.On("RefreshTokens", mock.Anything, mock.Anything).
		Return(nil, user.ErrTokenInvalid)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh",
		jsonBody(t, map[string]any{"refresh_token": "bad-token"}))
	req.Header.Set("Content-Type", "application/json")
	authRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "TOKEN_INVALID", resp["code"])
}

func TestAuthRefresh_MissingRefreshToken_Returns400(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh",
		jsonBody(t, map[string]any{}))
	req.Header.Set("Content-Type", "application/json")
	authRouter(&mockAuthSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── POST /auth/logout ─────────────────────────────────────────────────────────

func TestAuthLogout_Returns204(t *testing.T) {
	svc := &mockAuthSvc{}
	svc.On("Logout", mock.Anything, "some-refresh").Return(nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/logout",
		jsonBody(t, map[string]any{"refresh_token": "some-refresh"}))
	req.Header.Set("Content-Type", "application/json")
	authRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestAuthLogout_EmptyBody_StillReturns204(t *testing.T) {
	// Logout is idempotent — empty body is fine.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/logout",
		bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	authRouter(&mockAuthSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

// ── GET /auth/profile ─────────────────────────────────────────────────────────

func TestAuthGetProfile_WithUserID_Returns200(t *testing.T) {
	svc := &mockAuthSvc{}
	svc.On("GetProfile", mock.Anything, "u-1").Return(sampleAuthUser(), nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	authRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "alice@example.com", resp["email"])
	assert.Equal(t, "Alice", resp["first_name"])
	svc.AssertExpectations(t)
}

func TestAuthGetProfile_NoUserIDInContext_Returns401(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/profile/unauth", nil)
	authRouter(&mockAuthSvc{}).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "UNAUTHENTICATED", resp["code"])
}

func TestAuthGetProfile_UserNotFound_Returns404(t *testing.T) {
	svc := &mockAuthSvc{}
	svc.On("GetProfile", mock.Anything, "u-1").Return(nil, user.ErrUserNotFound)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/profile", nil)
	authRouter(svc).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "USER_NOT_FOUND", resp["code"])
}
