package memory

import (
	"errors"
	"log"
	"sync"

	authDomain "github.com/rabbicse/auth-service/internal/domain/aggregates/authentication"
)

type LoginChallengeRepo struct {
	mu sync.Mutex
	m  map[string]*authDomain.LoginChallenge
}

func NewLoginChallengeRepo() *LoginChallengeRepo {
	return &LoginChallengeRepo{m: map[string]*authDomain.LoginChallenge{}}
}

func (r *LoginChallengeRepo) Save(c *authDomain.LoginChallenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	log.Println("CHALLENGE SAVED:", c.ID)
	r.m[c.ID] = c
	return nil
}

func (r *LoginChallengeRepo) Find(id string) (*authDomain.LoginChallenge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	log.Println("CHALLENGE LOOKUP:", id)
	c, ok := r.m[id]
	if !ok {
		log.Println("CHALLENGE NOT FOUND")
		return nil, errors.New("not found")
	}
	return c, nil
}

func (r *LoginChallengeRepo) MarkUsed(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[id].Used = true
	return nil
}
