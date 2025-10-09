package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	ServerAddress string
	UploadPath    string
	LogLevel      string
	MaxUploadSize int64
	JWTSecret     string
}

func Load() *Config {
	// Load .env file if exists
	godotenv.Load()

	config := &Config{
		ServerAddress: getEnv("SERVER_ADDRESS", ":8080"),
		UploadPath:    getEnv("UPLOAD_PATH", "./static/uploads"),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		MaxUploadSize: getEnvAsInt64("MAX_UPLOAD_SIZE", 100<<20), // 100MB default
		JWTSecret:     getEnv("JWT_SECRET", "magicstream-secret"),
	}

	// Create upload directory if it doesn't exist
	if err := os.MkdirAll(config.UploadPath, 0755); err != nil {
		log.Fatalf("Failed to create upload directory: %v", err)
	}

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}
