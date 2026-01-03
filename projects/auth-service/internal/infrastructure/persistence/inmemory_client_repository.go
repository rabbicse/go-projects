package persistence

import (
	"sync"

	"github.com/rabbicse/auth-service/internal/domain/aggregates/client"
	"github.com/rabbicse/auth-service/internal/domain/repositories"
)

type InMemoryClientRepository struct {
	clients map[string]*client.Client
	mu      sync.RWMutex
	factory *client.ClientFactory
}

func NewInMemoryClientRepository(factory *client.ClientFactory) repositories.ClientRepository {
	repo := &InMemoryClientRepository{
		clients: make(map[string]*client.Client),
		factory: factory,
	}

	// Seed with sample data
	repo.seedData()

	return repo
}

func (r *InMemoryClientRepository) FindByID(id string) (*client.Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	clientAgg, exists := r.clients[id]
	if !exists {
		return nil, &repositories.ClientNotFoundError{ClientID: id}
	}

	return clientAgg, nil
}

func (r *InMemoryClientRepository) FindByName(name string) (*client.Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, clientAgg := range r.clients {
		if clientAgg.Name() == name {
			return clientAgg, nil
		}
	}

	return nil, &repositories.ClientNotFoundError{ClientID: name}
}

func (r *InMemoryClientRepository) Save(clientAgg *client.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.clients[clientAgg.ID().Value()] = clientAgg
	clientAgg.ClearEvents()

	return nil
}

func (r *InMemoryClientRepository) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.clients, id)
	return nil
}

func (r *InMemoryClientRepository) List(offset, limit int) ([]*client.Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var clients []*client.Client
	count := 0

	for _, clientAgg := range r.clients {
		if count >= offset && (limit == 0 || len(clients) < limit) {
			clients = append(clients, clientAgg)
		}
		count++
	}

	return clients, nil
}

func (r *InMemoryClientRepository) Exists(id string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.clients[id]
	return exists, nil
}

func (r *InMemoryClientRepository) seedData() {
	// Create sample confidential client
	confidentialClient, _ := r.factory.CreateConfidentialClient(
		"test-client",
		"Test Client Application",
		"test-secret",
		[]string{"http://localhost:3000/callback"},
		[]string{"read", "write", "profile"},
	)

	// Create sample public client
	publicClient, _ := r.factory.CreatePublicClient(
		"public-client",
		"Public SPA Application",
		[]string{"http://localhost:3001/callback"},
		[]string{"read", "openid"},
	)

	r.clients[confidentialClient.ID().Value()] = confidentialClient
	r.clients[publicClient.ID().Value()] = publicClient
}
