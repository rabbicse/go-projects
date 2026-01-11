package memory

import (
	"errors"
	"log"
	"sync"

	authchallenge "github.com/rabbicse/auth-service/internal/domain/challenge"
)

type ChallengeRepo struct {
	mu sync.Mutex
	m  map[string]*authchallenge.Challenge
}

func NewChallengeRepo() *ChallengeRepo {
	return &ChallengeRepo{m: map[string]*authchallenge.Challenge{}}
}

func (r *ChallengeRepo) Save(c *authchallenge.Challenge) {
	r.mu.Lock()
	defer r.mu.Unlock()
	log.Println("CHALLENGE SAVED:", c.ID)
	r.m[c.ID] = c
}

func (r *ChallengeRepo) Find(id string) (*authchallenge.Challenge, error) {
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

func (r *ChallengeRepo) MarkUsed(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[id].Used = true
}
