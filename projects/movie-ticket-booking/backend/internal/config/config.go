package config

import (
	"log/slog"
	"net/url"
	"time"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	Server  ServerConfig
	Redis   RedisConfig
	MongoDB MongoDBConfig
	Booking BookingConfig
	Admin   AdminConfig
	Auth    AuthConfig
}

type AuthConfig struct {
	// JWKSEndpoint enables external RS256 validation (e.g. future OAuth2/PKCE provider).
	// Leave empty when using built-in HS256 auth (JWT_SECRET).
	JWKSEndpoint string `env:"AUTH_JWKS_ENDPOINT" envDefault:""`

	// JWTSecret enables built-in HS256 auth. Must be ≥32 chars in production.
	// Extension point: swap for RSA key path when upgrading to RS256/PKCE.
	JWTSecret string `env:"JWT_SECRET" envDefault:""`

	// RefreshTokenTTL controls how long refresh tokens remain valid (default 7 days).
	RefreshTokenTTL time.Duration `env:"REFRESH_TOKEN_TTL" envDefault:"168h"`
}

type ServerConfig struct {
	Port         int           `env:"SERVER_PORT"          envDefault:"8080"`
	Host         string        `env:"SERVER_HOST"          envDefault:"0.0.0.0"`
	ReadTimeout  time.Duration `env:"SERVER_READ_TIMEOUT"  envDefault:"10s"`
	WriteTimeout time.Duration `env:"SERVER_WRITE_TIMEOUT" envDefault:"10s"`
	Mode         string        `env:"GIN_MODE"             envDefault:"debug"`
}

type RedisConfig struct {
	Addr     string `env:"REDIS_ADDR"     envDefault:"localhost:6379"`
	Password string `env:"REDIS_PASSWORD" envDefault:""`
	DB       int    `env:"REDIS_DB"       envDefault:"0"`
}

type MongoDBConfig struct {
	URI      string `env:"MONGODB_URI"      envDefault:"mongodb://localhost:27017"`
	Database string `env:"MONGODB_DATABASE" envDefault:"movie_ticket_booking"`
}

type BookingConfig struct {
	MaxSeatsPerSession int           `env:"MAX_SEATS_PER_SESSION" envDefault:"4"`
	HoldTTL            time.Duration `env:"HOLD_TTL"              envDefault:"10m"`
}

type AdminConfig struct {
	User     string `env:"ADMIN_USER"     envDefault:"admin"`
	Password string `env:"ADMIN_PASSWORD" envDefault:"changeme"`
}

func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	slog.Info("config loaded",
		"server_port", cfg.Server.Port,
		"redis_addr", cfg.Redis.Addr,
		"mongo_host", mongoHost(cfg.MongoDB.URI), // never log the full URI — may contain password
		"max_seats", cfg.Booking.MaxSeatsPerSession,
		"hold_ttl", cfg.Booking.HoldTTL,
	)
	return cfg, nil
}

// mongoHost extracts only the host:port from a MongoDB URI so credentials
// in the URI (mongodb://user:pass@host:port/db) are never written to logs.
func mongoHost(uri string) string {
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" {
		return "unknown"
	}
	return u.Host
}
