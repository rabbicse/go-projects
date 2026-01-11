package repository

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisRepo struct {
	client *redis.ClusterClient
}

func NewRedisRepo(addrs []string) (*RedisRepo, error) {
	// client := redis.NewClient(&redis.Options{
	// 	Addr:     host + ":" + port,
	// 	Password: "",
	// 	DB:       0,
	// 	PoolSize: 100,
	// })

	// Redis Cluster
	client := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:          addrs,
		Password:       "", // no password
		PoolSize:       100,
		MaxRetries:     3,
		DialTimeout:    5 * time.Second,
		ReadTimeout:    3 * time.Second,
		WriteTimeout:   3 * time.Second,
		RouteRandomly:  true, // Distribute reads across replicas
		RouteByLatency: true, // Route to the closest node
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ping the cluster to verify the connection
	pong, err := client.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Could not connect to Redis Cluster: %v", err)
	}
	fmt.Println("Connected to Redis Cluster:", pong)

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
