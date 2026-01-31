package memory

import (
	"context"
	"sync"

	"github.com/rabbicse/auth-service/internal/domain"
	"github.com/rabbicse/auth-service/internal/domain/aggregates/client"
)

type ClientRepository struct {
	mu      sync.RWMutex
	clients map[string]*client.Client
}

func NewClientRepository(seed []*client.Client) *ClientRepository {
	m := make(map[string]*client.Client)
	for _, c := range seed {
		m[c.ID] = c
	}
	return &ClientRepository{clients: m}
}

func (r *ClientRepository) FindByID(ctx context.Context, id string) (*client.Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	c, ok := r.clients[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return c, nil
}
