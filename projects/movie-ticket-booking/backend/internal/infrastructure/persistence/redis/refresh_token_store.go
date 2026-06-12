package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	authapp "github.com/rabbicse/movie-ticket-booking/internal/application/auth"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/user"
)

// refreshDoc is the JSON shape stored in Redis for each refresh token.
type refreshDoc struct {
	UserID    string           `json:"user_id"`
	Roles     []user.RoleType  `json:"roles"`
	ExpiresAt time.Time        `json:"expires_at"`
}

// RefreshTokenStore implements authapp.RefreshStore using Redis.
// Key schema: refresh:{token}  (TTL = time until ExpiresAt, matches RefreshSession.ExpiresAt)
// Does not conflict with existing seat and session keys.
type RefreshTokenStore struct {
	client *redis.Client
}

func NewRefreshTokenStore(client *redis.Client) *RefreshTokenStore {
	return &RefreshTokenStore{client: client}
}

func (s *RefreshTokenStore) Save(
	ctx context.Context,
	token, userID string,
	roles []user.RoleType,
	expiresAt time.Time,
) error {
	doc := refreshDoc{UserID: userID, Roles: roles, ExpiresAt: expiresAt}
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("marshal refresh token: %w", err)
	}
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired")
	}
	return s.client.Set(ctx, refreshKey(token), data, ttl).Err()
}

func (s *RefreshTokenStore) Get(ctx context.Context, token string) (*authapp.RefreshSession, error) {
	data, err := s.client.Get(ctx, refreshKey(token)).Bytes()
	if err != nil {
		return nil, fmt.Errorf("refresh token not found: %w", err)
	}
	var doc refreshDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("corrupt refresh token: %w", err)
	}
	return &authapp.RefreshSession{
		UserID:    doc.UserID,
		Roles:     doc.Roles,
		ExpiresAt: doc.ExpiresAt,
	}, nil
}

func (s *RefreshTokenStore) Delete(ctx context.Context, token string) error {
	return s.client.Del(ctx, refreshKey(token)).Err()
}

func refreshKey(token string) string {
	return "refresh:" + token
}
