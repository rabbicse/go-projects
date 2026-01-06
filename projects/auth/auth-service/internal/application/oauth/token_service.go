package oauth

import "context"

type TokenService interface {
	Token(ctx context.Context, req TokenRequest) (*TokenResponse, error)
}
