package memory

import (
	"errors"
	"sync"
	"time"

	"github.com/rabbicse/auth-service/internal/domain/aggregates/token"
)

type InMemoryRefreshStore struct {
	data sync.Map
}

func NewInMemoryRefreshStore() *InMemoryRefreshStore {
	return &InMemoryRefreshStore{}
}

func (s *InMemoryRefreshStore) Save(
	t string,
	userID string,
	clientID string,
	exp time.Time,
) error {
	s.data.Store(t, &token.RefreshSession{
		Token:     t,
		UserID:    userID,
		ClientID:  clientID,
		ExpiresAt: exp,
	})

	return nil
}

func (s *InMemoryRefreshStore) Get(
	t string,
) (*token.RefreshSession, error) {

	val, ok := s.data.Load(t)
	if !ok {
		return nil, errors.New("invalid refresh token")
	}

	session := val.(*token.RefreshSession)

	if time.Now().After(session.ExpiresAt) {
		s.data.Delete(t)
		return nil, errors.New("expired refresh token")
	}

	return session, nil
}

func (s *InMemoryRefreshStore) Delete(t string) error {
	s.data.Delete(t)
	return nil
}
