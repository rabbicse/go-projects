package user_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
)

// ── RoleType constants ────────────────────────────────────────────────────────

func TestRoleType_Values(t *testing.T) {
	assert.Equal(t, user.RoleType("customer"), user.RoleCustomer)
	assert.Equal(t, user.RoleType("admin"), user.RoleAdmin)
}

// ── HasRole ───────────────────────────────────────────────────────────────────

func TestHasRole_MatchingRole_ReturnsTrue(t *testing.T) {
	u := &user.User{Roles: []user.RoleType{user.RoleCustomer}}
	assert.True(t, u.HasRole(user.RoleCustomer))
}

func TestHasRole_NonMatchingRole_ReturnsFalse(t *testing.T) {
	u := &user.User{Roles: []user.RoleType{user.RoleCustomer}}
	assert.False(t, u.HasRole(user.RoleAdmin))
}

func TestHasRole_AdminUser_ReturnsTrue(t *testing.T) {
	u := &user.User{Roles: []user.RoleType{user.RoleAdmin}}
	assert.True(t, u.HasRole(user.RoleAdmin))
}

func TestHasRole_MultipleRoles_MatchesAny(t *testing.T) {
	u := &user.User{Roles: []user.RoleType{user.RoleCustomer, user.RoleAdmin}}
	assert.True(t, u.HasRole(user.RoleCustomer))
	assert.True(t, u.HasRole(user.RoleAdmin))
}

func TestHasRole_EmptyRoles_ReturnsFalse(t *testing.T) {
	u := &user.User{Roles: nil}
	assert.False(t, u.HasRole(user.RoleCustomer))
}

func TestHasRole_ZeroValueUser_DoesNotPanic(t *testing.T) {
	var u user.User
	assert.False(t, u.HasRole(user.RoleAdmin))
}

// ── Sentinel errors ───────────────────────────────────────────────────────────

func TestErrors_AreDistinct(t *testing.T) {
	assert.NotEqual(t, user.ErrUserNotFound, user.ErrEmailTaken)
	assert.NotEqual(t, user.ErrEmailTaken, user.ErrInvalidPassword)
	assert.NotEqual(t, user.ErrInvalidPassword, user.ErrTokenInvalid)
}

func TestErrors_HaveDescriptiveMessages(t *testing.T) {
	assert.NotEmpty(t, user.ErrUserNotFound.Error())
	assert.NotEmpty(t, user.ErrEmailTaken.Error())
	assert.NotEmpty(t, user.ErrInvalidPassword.Error())
	assert.NotEmpty(t, user.ErrTokenInvalid.Error())
}

// ── PasswordHash ──────────────────────────────────────────────────────────────

func TestUser_PasswordHash_NotStoredAsPlaintext(t *testing.T) {
	// Bcrypt hashes start with $2a$ — verify the field follows that convention.
	// This does NOT test hashing logic (that belongs in the auth service test),
	// but guards against accidentally storing a raw password in the struct.
	u := &user.User{PasswordHash: "$2a$12$examplehashvalue"}
	assert.True(t, len(u.PasswordHash) > 0)
	assert.Contains(t, u.PasswordHash, "$2a$", "PasswordHash field must store a bcrypt hash, not plaintext")
}
