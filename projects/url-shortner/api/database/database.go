package database

import (
	"context"

	"github.com/redis/go-redis/v9"
)

var Ctx = context.Background()

func CreateClient(dbNo int) *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",   // no password set
		DB:       dbNo, // use default DB
	})

	return rdb
}
