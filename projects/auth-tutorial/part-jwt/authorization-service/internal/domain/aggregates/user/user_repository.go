package user

import (
	"context"
)

type UserRepository interface {
	FindByID(ctx context.Context, id string) (*User, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByUsername(username string) (*User, error)
	Save(u *User) error
}
