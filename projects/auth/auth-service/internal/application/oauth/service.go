package oauth

import "context"

type Service interface {
	Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResponse, error)
	Token(ctx context.Context, req TokenRequest) (*TokenResponse, error)
}
