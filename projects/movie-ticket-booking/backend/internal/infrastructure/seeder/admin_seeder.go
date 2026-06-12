package seeder

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
)

const (
	defaultAdminEmail    = "admin@cinebook.local"
	defaultAdminPassword = "Admin1234!"
)

// SeedAdminUser creates a default admin account on first boot if the address is not
// already registered. Logs a WARN with credentials — change the password in production.
func SeedAdminUser(ctx context.Context, repo user.Repository) error {
	_, err := repo.FindByEmail(ctx, defaultAdminEmail)
	if err == nil {
		return nil // already exists
	}
	if !errors.Is(err, user.ErrUserNotFound) {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(defaultAdminPassword), 12)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	admin := &user.User{
		ID:           uuid.NewString(),
		Email:        defaultAdminEmail,
		PasswordHash: string(hash),
		FirstName:    "Admin",
		LastName:     "",
		Roles:        []user.RoleType{user.RoleAdmin, user.RoleCustomer},
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := repo.Save(ctx, admin); err != nil {
		return err
	}

	slog.Warn("default admin created — change the password before going to production",
		"email", defaultAdminEmail,
		"password", defaultAdminPassword,
	)
	return nil
}
