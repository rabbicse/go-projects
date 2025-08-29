package loadbalancer

import (
	"errors"
	"sync"
	"time"
)

type BackendServer struct {
	URL       string
	Healthy   bool
	LastCheck time.Time
}

type RoundRobinLoadBalancer struct {
	servers []*BackendServer
	current int
	mu      sync.Mutex
}

func NewRoundRobinLoadBalancer(serverURLs []string) *RoundRobinLoadBalancer {
	servers := make([]*BackendServer, len(serverURLs))
	for i, url := range serverURLs {
		servers[i] = &BackendServer{
			URL:     url,
			Healthy: true,
		}
	}

	return &RoundRobinLoadBalancer{
		servers: servers,
		current: 0,
	}
}

func (lb *RoundRobinLoadBalancer) GetNextServer() (string, error) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if len(lb.servers) == 0 {
		return "", ErrNoHealthyServers
	}

	// Find next healthy server
	for i := 0; i < len(lb.servers); i++ {
		lb.current = (lb.current + 1) % len(lb.servers)
		if lb.servers[lb.current].Healthy {
			return lb.servers[lb.current].URL, nil
		}
	}

	return "", ErrNoHealthyServers
}

func (lb *RoundRobinLoadBalancer) SetServerHealth(url string, healthy bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for _, server := range lb.servers {
		if server.URL == url {
			server.Healthy = healthy
			server.LastCheck = time.Now()
			break
		}
	}
}

func (lb *RoundRobinLoadBalancer) GetServerStatus() map[string]bool {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	status := make(map[string]bool)
	for _, server := range lb.servers {
		status[server.URL] = server.Healthy
	}
	return status
}

var ErrNoHealthyServers = errors.New("no healthy servers available")
