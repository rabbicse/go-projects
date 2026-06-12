package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
)

const (
	accessTokenTTL = 15 * time.Minute
	bcryptCost     = 12
	issuer         = "cinebook"
)

// RefreshStore is the persistence contract for opaque refresh tokens.
// Implementations live in infrastructure (Redis).
type RefreshStore interface {
	Save(ctx context.Context, token, userID string, roles []user.RoleType, expiresAt time.Time) error
	Get(ctx context.Context, token string) (*RefreshSession, error)
	Delete(ctx context.Context, token string) error
}

// RefreshSession holds the payload stored alongside each refresh token.
type RefreshSession struct {
	UserID    string
	Roles     []user.RoleType
	ExpiresAt time.Time
}

// Claims is the JWT access token payload (HS256).
type Claims struct {
	Roles []string `json:"roles"`
	Email string   `json:"email"`
	jwt.RegisteredClaims
}

// RegisterInput carries validated fields for new user creation.
type RegisterInput struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
}

// TokenPair is returned on successful login or token refresh.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64 // seconds until the access token expires
}

// Service handles all authentication use cases.
type Service struct {
	userRepo     user.Repository
	refreshStore RefreshStore
	jwtSecret    []byte
	refreshTTL   time.Duration
}

func NewService(userRepo user.Repository, refreshStore RefreshStore, jwtSecret string, refreshTTL time.Duration) *Service {
	return &Service{
		userRepo:     userRepo,
		refreshStore: refreshStore,
		jwtSecret:    []byte(jwtSecret),
		refreshTTL:   refreshTTL,
	}
}

// Register creates a new customer account and immediately issues tokens.
func (s *Service) Register(ctx context.Context, in RegisterInput) (*user.User, *TokenPair, error) {
	// Check uniqueness before hashing to fail fast.
	if _, err := s.userRepo.FindByEmail(ctx, in.Email); err == nil {
		return nil, nil, user.ErrEmailTaken
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcryptCost)
	if err != nil {
		return nil, nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	u := &user.User{
		ID:           uuid.NewString(),
		Email:        in.Email,
		PasswordHash: string(hash),
		FirstName:    in.FirstName,
		LastName:     in.LastName,
		Roles:        []user.RoleType{user.RoleCustomer},
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.userRepo.Save(ctx, u); err != nil {
		return nil, nil, err
	}

	tokens, err := s.issueTokenPair(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	return u, tokens, nil
}

// Login validates credentials and returns a fresh token pair.
func (s *Service) Login(ctx context.Context, email, password string) (*TokenPair, error) {
	u, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		// Run bcrypt on a dummy hash even on miss to prevent user-enumeration via timing side-channel.
		_ = bcrypt.CompareHashAndPassword(
			[]byte("$2a$12$placeholderplaceholderplaceholde"), []byte(password))
		return nil, user.ErrInvalidPassword
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, user.ErrInvalidPassword
	}

	return s.issueTokenPair(ctx, u)
}

// RefreshTokens rotates the refresh token and issues a new access token.
// The old refresh token is invalidated before the new pair is issued.
func (s *Service) RefreshTokens(ctx context.Context, refreshToken string) (*TokenPair, error) {
	session, err := s.refreshStore.Get(ctx, refreshToken)
	if err != nil || time.Now().After(session.ExpiresAt) {
		return nil, user.ErrTokenInvalid
	}

	u, err := s.userRepo.FindByID(ctx, session.UserID)
	if err != nil {
		return nil, user.ErrTokenInvalid
	}

	// Delete first — if issueTokenPair fails the old token is gone; client must re-login.
	// This prevents replay attacks at the cost of a rare "thundering herd" re-login.
	if err := s.refreshStore.Delete(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	return s.issueTokenPair(ctx, u)
}

// Logout invalidates the supplied refresh token. Idempotent — missing token is not an error.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	_ = s.refreshStore.Delete(ctx, refreshToken)
	return nil
}

// GetProfile returns the user record for an authenticated user ID.
func (s *Service) GetProfile(ctx context.Context, userID string) (*user.User, error) {
	return s.userRepo.FindByID(ctx, userID)
}

// ValidateAccessToken parses and validates an HS256 JWT, returning the embedded claims.
// Used by the RequireAuth middleware to avoid a dependency on this service package.
func (s *Service) ValidateAccessToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, user.ErrTokenInvalid
	}
	return claims, nil
}

// issueTokenPair generates an HS256 access token and a cryptographically random refresh token.
func (s *Service) issueTokenPair(ctx context.Context, u *user.User) (*TokenPair, error) {
	roles := make([]string, len(u.Roles))
	for i, r := range u.Roles {
		roles[i] = string(r)
	}

	now := time.Now().UTC()
	exp := now.Add(accessTokenTTL)

	claims := Claims{
		Roles: roles,
		Email: u.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	refreshToken, err := generateOpaqueToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	refreshRoles := make([]user.RoleType, len(u.Roles))
	copy(refreshRoles, u.Roles)

	expiresAt := now.Add(s.refreshTTL)
	if err := s.refreshStore.Save(ctx, refreshToken, u.ID, refreshRoles, expiresAt); err != nil {
		return nil, fmt.Errorf("persist refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(accessTokenTTL.Seconds()),
	}, nil
}

func generateOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
