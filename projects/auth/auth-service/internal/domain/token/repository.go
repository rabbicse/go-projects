package token

import "context"

type Repository interface {
	Save(ctx context.Context, token *Token) error
	FindByAccessToken(ctx context.Context, token string) (*Token, error)
	Revoke(ctx context.Context, token string) error
}
