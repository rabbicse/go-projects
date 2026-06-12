package user

import (
	"context"
	"errors"
	"time"
)

// RoleType is a typed string that prevents raw string role comparisons across the codebase.
type RoleType string

const (
	RoleCustomer RoleType = "customer"
	RoleAdmin    RoleType = "admin"
	// Future roles (OAuth2 scopes, MFA tier, etc.) extend this block only.
)

// User is the aggregate root for the user bounded context.
type User struct {
	ID           string
	Email        string
	PasswordHash string // bcrypt hash; never stored or logged as plaintext
	FirstName    string
	LastName     string
	Roles        []RoleType
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func (u *User) HasRole(role RoleType) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Repository is the persistence contract for the User aggregate.
// Implementations live in infrastructure; the domain never imports them.
type Repository interface {
	FindByID(ctx context.Context, id string) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	Save(ctx context.Context, u *User) error
	EnsureIndexes(ctx context.Context) error
}

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrEmailTaken      = errors.New("email already registered")
	ErrInvalidPassword = errors.New("invalid credentials")
	ErrTokenInvalid    = errors.New("token invalid or expired")
)
