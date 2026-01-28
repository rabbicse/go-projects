package client

import "context"

type ClientRepository interface {
	FindByID(ctx context.Context, id string) (*Client, error)
}
