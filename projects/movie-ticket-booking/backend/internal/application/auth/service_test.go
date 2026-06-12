package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	authapp "github.com/rabbicse/movie-ticket-booking/internal/application/auth"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
)

// ── Mocks ─────────────────────────────────────────────────────────────────────

type mockUserRepo struct{ mock.Mock }

func (m *mockUserRepo) FindByID(ctx context.Context, id string) (*user.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}
func (m *mockUserRepo) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}
func (m *mockUserRepo) Save(ctx context.Context, u *user.User) error {
	return m.Called(ctx, u).Error(0)
}
func (m *mockUserRepo) EnsureIndexes(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

type mockRefreshStore struct{ mock.Mock }

func (m *mockRefreshStore) Save(ctx context.Context, token, userID string, roles []user.RoleType, expiresAt time.Time) error {
	return m.Called(ctx, token, userID, roles, expiresAt).Error(0)
}
func (m *mockRefreshStore) Get(ctx context.Context, token string) (*authapp.RefreshSession, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*authapp.RefreshSession), args.Error(1)
}
func (m *mockRefreshStore) Delete(ctx context.Context, token string) error {
	return m.Called(ctx, token).Error(0)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func newAuthService(t *testing.T) (*authapp.Service, *mockUserRepo, *mockRefreshStore) {
	t.Helper()
	ur := &mockUserRepo{}
	rs := &mockRefreshStore{}
	return authapp.NewService(ur, rs, "test-jwt-secret", 7*24*time.Hour), ur, rs
}

// fastHash returns a bcrypt hash at MinCost (4) for quick login tests.
func fastHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	require.NoError(t, err)
	return string(h)
}

func sampleUser() *user.User {
	return &user.User{
		ID:        "u-1",
		Email:     "alice@example.com",
		FirstName: "Alice",
		LastName:  "Smith",
		Roles:     []user.RoleType{user.RoleCustomer},
	}
}

// ── Register ──────────────────────────────────────────────────────────────────

func TestRegister_Success(t *testing.T) {
	svc, ur, rs := newAuthService(t)
	ctx := context.Background()

	ur.On("FindByEmail", ctx, "alice@example.com").Return(nil, user.ErrUserNotFound)
	ur.On("Save", ctx, mock.AnythingOfType("*user.User")).Return(nil)
	rs.On("Save", ctx, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	u, tokens, err := svc.Register(ctx, authapp.RegisterInput{
		Email:     "alice@example.com",
		Password:  "s3cr3t99!",
		FirstName: "Alice",
	})

	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, "alice@example.com", u.Email)
	assert.Equal(t, []user.RoleType{user.RoleCustomer}, u.Roles)
	assert.NotEmpty(t, u.ID)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.Equal(t, int64(900), tokens.ExpiresIn) // 15 min
	ur.AssertExpectations(t)
	rs.AssertExpectations(t)
}

func TestRegister_DuplicateEmail_ReturnsErrEmailTaken(t *testing.T) {
	svc, ur, _ := newAuthService(t)
	ctx := context.Background()

	ur.On("FindByEmail", ctx, "taken@example.com").Return(sampleUser(), nil)

	_, _, err := svc.Register(ctx, authapp.RegisterInput{
		Email: "taken@example.com", Password: "password1!", FirstName: "Bob",
	})

	assert.ErrorIs(t, err, user.ErrEmailTaken)
	ur.AssertExpectations(t)
}

func TestRegister_SaveFails_ReturnsError(t *testing.T) {
	svc, ur, _ := newAuthService(t)
	ctx := context.Background()

	ur.On("FindByEmail", ctx, "new@example.com").Return(nil, user.ErrUserNotFound)
	ur.On("Save", ctx, mock.AnythingOfType("*user.User")).Return(assert.AnError)

	_, _, err := svc.Register(ctx, authapp.RegisterInput{
		Email: "new@example.com", Password: "password1!", FirstName: "New",
	})

	assert.Error(t, err)
}

// ── Login ─────────────────────────────────────────────────────────────────────

func TestLogin_Success(t *testing.T) {
	svc, ur, rs := newAuthService(t)
	ctx := context.Background()

	u := sampleUser()
	u.PasswordHash = fastHash(t, "mypassword")

	ur.On("FindByEmail", ctx, u.Email).Return(u, nil)
	rs.On("Save", ctx, mock.Anything, u.ID, mock.Anything, mock.Anything).Return(nil)

	tokens, err := svc.Login(ctx, u.Email, "mypassword")

	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	ur.AssertExpectations(t)
}

func TestLogin_WrongPassword_ReturnsErrInvalidPassword(t *testing.T) {
	svc, ur, _ := newAuthService(t)
	ctx := context.Background()

	u := sampleUser()
	u.PasswordHash = fastHash(t, "correct-pass")
	ur.On("FindByEmail", ctx, u.Email).Return(u, nil)

	_, err := svc.Login(ctx, u.Email, "wrong-pass")

	assert.ErrorIs(t, err, user.ErrInvalidPassword)
}

func TestLogin_UserNotFound_ReturnsErrInvalidPassword_NotErrUserNotFound(t *testing.T) {
	// Must return ErrInvalidPassword (not ErrUserNotFound) to prevent user enumeration.
	svc, ur, _ := newAuthService(t)
	ctx := context.Background()

	ur.On("FindByEmail", ctx, "ghost@example.com").Return(nil, user.ErrUserNotFound)

	_, err := svc.Login(ctx, "ghost@example.com", "anypassword")

	assert.ErrorIs(t, err, user.ErrInvalidPassword)
	assert.NotErrorIs(t, err, user.ErrUserNotFound)
}

// ── RefreshTokens ─────────────────────────────────────────────────────────────

func TestRefreshTokens_ValidToken_RotatesAndIssuesNewPair(t *testing.T) {
	svc, ur, rs := newAuthService(t)
	ctx := context.Background()

	session := &authapp.RefreshSession{
		UserID:    "u-1",
		Roles:     []user.RoleType{user.RoleCustomer},
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}
	rs.On("Get", ctx, "old-refresh").Return(session, nil)
	ur.On("FindByID", ctx, "u-1").Return(sampleUser(), nil)
	rs.On("Delete", ctx, "old-refresh").Return(nil)
	rs.On("Save", ctx, mock.Anything, "u-1", mock.Anything, mock.Anything).Return(nil)

	tokens, err := svc.RefreshTokens(ctx, "old-refresh")

	require.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	rs.AssertCalled(t, "Delete", ctx, "old-refresh") // old token deleted
}

func TestRefreshTokens_ExpiredSession_ReturnsErrTokenInvalid(t *testing.T) {
	svc, _, rs := newAuthService(t)
	ctx := context.Background()

	expired := &authapp.RefreshSession{
		UserID:    "u-1",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	rs.On("Get", ctx, "expired-token").Return(expired, nil)

	_, err := svc.RefreshTokens(ctx, "expired-token")

	assert.ErrorIs(t, err, user.ErrTokenInvalid)
}

func TestRefreshTokens_StoreReturnsError_ReturnsErrTokenInvalid(t *testing.T) {
	svc, _, rs := newAuthService(t)
	ctx := context.Background()

	rs.On("Get", ctx, "bad-token").Return(nil, user.ErrTokenInvalid)

	_, err := svc.RefreshTokens(ctx, "bad-token")

	assert.ErrorIs(t, err, user.ErrTokenInvalid)
}

// ── Logout ────────────────────────────────────────────────────────────────────

func TestLogout_DeletesRefreshToken(t *testing.T) {
	svc, _, rs := newAuthService(t)
	ctx := context.Background()

	rs.On("Delete", ctx, "some-refresh").Return(nil)

	err := svc.Logout(ctx, "some-refresh")

	assert.NoError(t, err)
	rs.AssertCalled(t, "Delete", ctx, "some-refresh")
}

func TestLogout_AlreadyDeletedToken_IsIdempotent(t *testing.T) {
	svc, _, rs := newAuthService(t)
	ctx := context.Background()

	rs.On("Delete", ctx, "gone").Return(user.ErrTokenInvalid)

	// Logout always returns nil regardless of store error.
	err := svc.Logout(ctx, "gone")

	assert.NoError(t, err)
}

// ── GetProfile ────────────────────────────────────────────────────────────────

func TestGetProfile_Success(t *testing.T) {
	svc, ur, _ := newAuthService(t)
	ctx := context.Background()

	expected := sampleUser()
	ur.On("FindByID", ctx, "u-1").Return(expected, nil)

	got, err := svc.GetProfile(ctx, "u-1")

	require.NoError(t, err)
	assert.Equal(t, expected.ID, got.ID)
	assert.Equal(t, expected.Email, got.Email)
}

func TestGetProfile_NotFound_ReturnsErrUserNotFound(t *testing.T) {
	svc, ur, _ := newAuthService(t)
	ctx := context.Background()

	ur.On("FindByID", ctx, "ghost").Return(nil, user.ErrUserNotFound)

	_, err := svc.GetProfile(ctx, "ghost")

	assert.ErrorIs(t, err, user.ErrUserNotFound)
}
