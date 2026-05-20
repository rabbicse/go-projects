package config

import (
	"log/slog"
	"time"

	"github.com/caarlos0/env/v11"
)

type Config struct {
	Server  ServerConfig
	Redis   RedisConfig
	MongoDB MongoDBConfig
	Booking BookingConfig
}

type ServerConfig struct {
	Port         int           `env:"SERVER_PORT"          envDefault:"8080"`
	Host         string        `env:"SERVER_HOST"          envDefault:"0.0.0.0"`
	ReadTimeout  time.Duration `env:"SERVER_READ_TIMEOUT"  envDefault:"10s"`
	WriteTimeout time.Duration `env:"SERVER_WRITE_TIMEOUT" envDefault:"10s"`
	Mode         string        `env:"GIN_MODE"             envDefault:"debug"`
}

type RedisConfig struct {
	Addr     string `env:"REDIS_ADDR"     envDefault:"192.168.0.50:6379"`
	Password string `env:"REDIS_PASSWORD" envDefault:""`
	DB       int    `env:"REDIS_DB"       envDefault:"0"`
}

type MongoDBConfig struct {
	URI      string `env:"MONGODB_URI"      envDefault:"mongodb://192.168.0.50:27017"`
	Database string `env:"MONGODB_DATABASE" envDefault:"movie_ticket_booking"`
}

type BookingConfig struct {
	MaxSeatsPerSession int           `env:"MAX_SEATS_PER_SESSION" envDefault:"4"`
	HoldTTL            time.Duration `env:"HOLD_TTL"              envDefault:"10m"`
}

func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}
	slog.Info("config loaded",
		"server_port", cfg.Server.Port,
		"redis_addr", cfg.Redis.Addr,
		"mongodb_uri", cfg.MongoDB.URI,
		"max_seats", cfg.Booking.MaxSeatsPerSession,
		"hold_ttl", cfg.Booking.HoldTTL,
	)
	return cfg, nil
}
