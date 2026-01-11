package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	APIBaseURL     string        `yaml:"api_base_url"`
	DefaultTimeout time.Duration `yaml:"default_timeout"`
	MaxWorkers     int           `yaml:"max_workers"`
	TestUsers      []TestUser    `yaml:"test_users"`
}

type TestUser struct {
	ID       string `yaml:"id"`
	APIToken string `yaml:"api_token"`
}

func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.APIBaseURL == "" {
		cfg.APIBaseURL = "http://localhost"
	}

	if cfg.DefaultTimeout == 0 {
		cfg.DefaultTimeout = 30 * time.Second
	}

	if cfg.MaxWorkers == 0 {
		cfg.MaxWorkers = 1000
	}

	return &cfg, nil
}
