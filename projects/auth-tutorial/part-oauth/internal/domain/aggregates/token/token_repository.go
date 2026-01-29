package token

import "context"

type TokenRepository interface {
	Save(ctx context.Context, token *Token) error
	FindByAccessToken(ctx context.Context, token string) (*Token, error)
	Revoke(ctx context.Context, token string) error
}
