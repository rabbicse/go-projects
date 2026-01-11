package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port                string
	BackendServers      []string
	RedisAddrs          []string
	JWTSecret           string
	RateLimitRequests   int
	RateLimitDuration   time.Duration
	CacheTTL            time.Duration
	EnableTracing       bool
	JaegerEndpoint      string
	HealthCheckInterval time.Duration
}

func LoadConfig() *Config {
	return &Config{
		Port:                getEnv("PORT", "3000"),
		BackendServers:      getEnvSlice("BACKEND_SERVERS", []string{"url-shortener-1:8080,url-shortener-2:8080,url-shortener-3:8080"}),
		RedisAddrs:          getEnvSlice("REDIS_ADDRS", []string{"redis:6379"}),
		JWTSecret:           getEnv("JWT_SECRET", "your-super-secret-jwt-key-change-in-production"),
		RateLimitRequests:   getEnvAsInt("RATE_LIMIT_REQUESTS", 100),
		RateLimitDuration:   time.Duration(getEnvAsInt("RATE_LIMIT_DURATION", 60)) * time.Second,
		CacheTTL:            time.Duration(getEnvAsInt("CACHE_TTL", 300)) * time.Second,
		EnableTracing:       getEnvAsBool("ENABLE_TRACING", false),
		JaegerEndpoint:      getEnv("JAEGER_ENDPOINT", "http://jaeger:14268/api/traces"),
		HealthCheckInterval: time.Duration(getEnvAsInt("HEALTH_CHECK_INTERVAL", 30)) * time.Second,
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// Add this helper function to parse comma-separated strings into slices
func getEnvSlice(key string, defaultVal []string) []string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	return strings.Split(val, ",")
}
