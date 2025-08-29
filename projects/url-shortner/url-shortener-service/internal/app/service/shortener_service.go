package service

import (
	"fmt"
	"log"
	"time"

	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/model"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/repository"
)

type ShortenerService struct {
	postgresRepo *repository.PostgresRepo
	redisRepo    *repository.RedisRepo
	baseURL      string
	generator    IDGenerator
}

type ShortnerServiceConfig struct {
	PostgresRepo *repository.PostgresRepo
	RedisRepo    *repository.RedisRepo
	BaseURL      string
	Generator    IDGenerator
}

func NewShortenerService(cfg *ShortnerServiceConfig) *ShortenerService {
	return &ShortenerService{
		postgresRepo: cfg.PostgresRepo,
		redisRepo:    cfg.RedisRepo,
		baseURL:      cfg.BaseURL,
		generator:    cfg.Generator, //utils.NewUniqueIDGenerator(machineID, 16, redisRepo),
	}
}

func (service *ShortenerService) ShortenURL(originalURL string) (*model.CreateResponse, error) {
	// Check if URL already exists
	existingCode, err := service.postgresRepo.GetURLByOriginalURL(originalURL)
	if err == nil {
		return &model.CreateResponse{
			ShortURL:    fmt.Sprintf("%s/%s", service.baseURL, existingCode),
			OriginalURL: originalURL,
			CreatedAt:   time.Now().UTC(),
		}, nil
	}

	// generate unique id
	shortCode, error := service.generator.GenerateID()
	log.Printf("Short Code: %v", shortCode)
	if error != nil {
		return nil, fmt.Errorf("failed to create URL: %v", err)
	}

	// Save to database
	if err := service.postgresRepo.CreateURL(shortCode, originalURL); err != nil {
		return nil, fmt.Errorf("failed to create URL: %v", err)
	}

	// Cache in Redis
	if err := service.redisRepo.SetURL(shortCode, originalURL, 24*time.Hour); err != nil {
		fmt.Printf("Warning: Failed to cache URL: %v\n", err)
	}

	return &model.CreateResponse{
		ShortURL:    fmt.Sprintf("%s/%s", service.baseURL, shortCode),
		OriginalURL: originalURL,
		CreatedAt:   time.Now().UTC(),
	}, nil
}
