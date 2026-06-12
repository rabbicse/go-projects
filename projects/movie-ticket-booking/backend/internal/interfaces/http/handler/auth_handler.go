package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	authapp "github.com/rabbicse/movie-ticket-booking/internal/application/auth"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/apierr"
	"github.com/rabbicse/movie-ticket-booking/internal/interfaces/http/middleware"
)

// ── request / response shapes ────────────────────────────────────────────────
// Kept inline (no separate dto file) because they are thin wrappers with no
// reuse outside this handler.

type registerRequest struct {
	Email     string `json:"email"      binding:"required,email"`
	Password  string `json:"password"   binding:"required,min=8"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name"`
}

type loginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type userResponse struct {
	ID        string   `json:"id"`
	Email     string   `json:"email"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	Roles     []string `json:"roles"`
	CreatedAt string   `json:"created_at"`
}

// ── helpers ──────────────────────────────────────────────────────────────────

func toUserResponse(u *user.User) userResponse {
	roles := make([]string, len(u.Roles))
	for i, r := range u.Roles {
		roles[i] = string(r)
	}
	return userResponse{
		ID:        u.ID,
		Email:     u.Email,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		Roles:     roles,
		CreatedAt: u.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

func toTokenResponse(tp *authapp.TokenPair) tokenResponse {
	return tokenResponse{
		AccessToken:  tp.AccessToken,
		RefreshToken: tp.RefreshToken,
		ExpiresIn:    tp.ExpiresIn,
		TokenType:    "Bearer",
	}
}

// ── handler ──────────────────────────────────────────────────────────────────

// AuthHandler handles registration, login, token refresh, logout and profile.
type AuthHandler struct {
	svc AuthService
}

func NewAuthHandler(svc AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// POST /api/v1/auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}

	u, tokens, err := h.svc.Register(c.Request.Context(), authapp.RegisterInput{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user":   toUserResponse(u),
		"tokens": toTokenResponse(tokens),
	})
}

// POST /api/v1/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}

	tokens, err := h.svc.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, toTokenResponse(tokens))
}

// POST /api/v1/auth/refresh
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apierr.New("INVALID_REQUEST", apierr.FormatBindError(err)))
		return
	}

	tokens, err := h.svc.RefreshTokens(c.Request.Context(), req.RefreshToken)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, toTokenResponse(tokens))
}

// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	var req logoutRequest
	// Missing body is treated as a no-op: logout is always idempotent.
	if err := c.ShouldBindJSON(&req); err == nil && req.RefreshToken != "" {
		_ = h.svc.Logout(c.Request.Context(), req.RefreshToken)
	}
	c.Status(http.StatusNoContent)
}

// GET /api/v1/auth/profile  — protected by RequireAuth middleware
func (h *AuthHandler) GetProfile(c *gin.Context) {
	userID := c.GetString(middleware.JWTUserIDKey)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, apierr.New("UNAUTHENTICATED", "authentication required"))
		return
	}

	u, err := h.svc.GetProfile(c.Request.Context(), userID)
	if err != nil {
		status, body := apierr.HTTPStatusFor(err)
		c.JSON(status, body)
		return
	}

	c.JSON(http.StatusOK, toUserResponse(u))
}
