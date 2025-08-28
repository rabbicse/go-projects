package repository

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisRepo struct {
	client *redis.Client
}

func NewRedisRepo(host, port string) (*RedisRepo, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     host + ":" + port,
		Password: "",
		DB:       0,
		PoolSize: 100,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisRepo{client: client}, nil
}

func (r *RedisRepo) SetURL(shortCode, originalURL string, expiration time.Duration) error {
	ctx := context.Background()
	return r.client.Set(ctx, "url:"+shortCode, originalURL, expiration).Err()
}

func (r *RedisRepo) GetURL(shortCode string) (string, error) {
	ctx := context.Background()
	return r.client.Get(ctx, "url:"+shortCode).Result()
}

func (r *RedisRepo) GetNextSequence(key ...string) (int64, error) {
	ctx := context.Background()
	seqKey := "snowflake:sequence" // default key
	if len(key) > 0 && key[0] != "" {
		seqKey = key[0]
	}
	return r.client.Incr(ctx, seqKey).Result()
}

func (r *RedisRepo) Close() error {
	return r.client.Close()
}
