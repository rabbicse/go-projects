package service

import (
	"fmt"
	"time"

	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/repository"
)

type RedirectService struct {
	postgresRepo *repository.PostgresRepo
	redisRepo    *repository.RedisRepo
}

func NewRedirectService(postgresRepo *repository.PostgresRepo, redisRepo *repository.RedisRepo) *RedirectService {
	return &RedirectService{
		postgresRepo: postgresRepo,
		redisRepo:    redisRepo,
	}
}

func (service *RedirectService) Redirect(shortCode string) (string, error) {
	// Try cache first
	originalURL, err := service.redisRepo.GetURL(shortCode)
	if err == nil {
		// Update click count in background
		// todo: need to use kafka for better analytics and user statistics
		go service.postgresRepo.IncrementClickCount(shortCode)
		return originalURL, nil
	}

	// Fallback to database
	originalURL, err = service.postgresRepo.GetURLByShortCode(shortCode)
	if err != nil {
		return "", fmt.Errorf("URL not found")
	}

	// Cache the result
	go service.redisRepo.SetURL(shortCode, originalURL, 24*time.Hour)

	// Update click count
	go service.postgresRepo.IncrementClickCount(shortCode)

	return originalURL, nil
}
