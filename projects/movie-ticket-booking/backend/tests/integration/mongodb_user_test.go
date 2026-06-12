package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
	mongoinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/mongodb"
)

func sampleUser(id, email string) *user.User {
	return &user.User{
		ID:           id,
		Email:        email,
		PasswordHash: "$2a$12$examplehashplaceholderXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
		FirstName:    "Test",
		LastName:     "User",
		Roles:        []user.RoleType{user.RoleCustomer},
		CreatedAt:    time.Now().UTC().Truncate(time.Millisecond),
		UpdatedAt:    time.Now().UTC().Truncate(time.Millisecond),
	}
}

// ── Save + FindByEmail ────────────────────────────────────────────────────────

func TestUserRepo_Save_AndFindByEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewUserRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	u := sampleUser("user-it-1", "alice@example.com")
	require.NoError(t, repo.Save(ctx, u))

	found, err := repo.FindByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, u.ID, found.ID)
	assert.Equal(t, u.Email, found.Email)
	assert.Equal(t, u.FirstName, found.FirstName)
	assert.Equal(t, u.LastName, found.LastName)
	assert.Equal(t, []user.RoleType{user.RoleCustomer}, found.Roles)
}

// ── FindByID ──────────────────────────────────────────────────────────────────

func TestUserRepo_FindByID_Found(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewUserRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	u := sampleUser("user-it-2", "bob@example.com")
	require.NoError(t, repo.Save(ctx, u))

	found, err := repo.FindByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, found.ID)
	assert.Equal(t, u.Email, found.Email)
}

func TestUserRepo_FindByID_NotFound_ReturnsErrUserNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewUserRepository(db)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "ghost-user-id")
	assert.ErrorIs(t, err, user.ErrUserNotFound)
}

func TestUserRepo_FindByEmail_NotFound_ReturnsErrUserNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewUserRepository(db)
	ctx := context.Background()

	_, err := repo.FindByEmail(ctx, "nobody@example.com")
	assert.ErrorIs(t, err, user.ErrUserNotFound)
}

// ── Unique email index enforcement ────────────────────────────────────────────

func TestUserRepo_DuplicateEmail_ReturnsErrEmailTaken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewUserRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	u1 := sampleUser("user-dup-1", "dup@example.com")
	require.NoError(t, repo.Save(ctx, u1))

	u2 := sampleUser("user-dup-2", "dup@example.com") // same email, different ID
	err := repo.Save(ctx, u2)
	assert.ErrorIs(t, err, user.ErrEmailTaken, "duplicate email must return ErrEmailTaken")
}

// ── Admin role ────────────────────────────────────────────────────────────────

func TestUserRepo_AdminRole_RoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	db := startMongoDB(t)
	repo := mongoinfra.NewUserRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.EnsureIndexes(ctx))

	u := sampleUser("admin-user-1", "admin@example.com")
	u.Roles = []user.RoleType{user.RoleAdmin}
	require.NoError(t, repo.Save(ctx, u))

	found, err := repo.FindByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, []user.RoleType{user.RoleAdmin}, found.Roles)
	assert.True(t, found.HasRole(user.RoleAdmin))
}
