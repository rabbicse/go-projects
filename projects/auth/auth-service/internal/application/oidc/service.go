package oidc

import "github.com/rabbicse/auth-service/internal/domain/user"

type Service interface {
	GenerateIDToken(
		user *user.User,
		clientID string,
		scopes []string,
	) (string, error)
}
