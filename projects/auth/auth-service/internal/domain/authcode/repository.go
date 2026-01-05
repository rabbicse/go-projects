package authcode

import "context"

type Repository interface {
	Save(ctx context.Context, code *AuthorizationCode) error
	Consume(ctx context.Context, code string) (*AuthorizationCode, error)
}
