package client

import "context"

type Repository interface {
	FindByID(ctx context.Context, id string) (*Client, error)
}
