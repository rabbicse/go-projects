package oauth

import "context"

type AuthorizationCodeRepository interface {
	Save(ctx context.Context, code *AuthorizationCode) error
	Get(ctx context.Context, code string) (*AuthorizationCode, error)
}
