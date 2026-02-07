package token

import "time"

type RefreshStore interface {
	Save(
		token string,
		userID string,
		clientID string,
		exp time.Time,
	) error
	Get(token string) (*RefreshSession, error)
	Delete(token string) error
}
