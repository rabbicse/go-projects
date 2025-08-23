package service

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/rabbicse/go-projects/projects/url-shortner/internal/model"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/repository"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/utils"
)

type URLService struct {
	postgresRepo *repository.PostgresRepo
	redisRepo    *repository.RedisRepo
	baseURL      string
}

func NewURLService(postgresRepo *repository.PostgresRepo, redisRepo *repository.RedisRepo, baseURL string) *URLService {
	return &URLService{
		postgresRepo: postgresRepo,
		redisRepo:    redisRepo,
		baseURL:      baseURL,
	}
}

func (s *URLService) CreateShortURL(originalURL string) (*model.CreateResponse, error) {
	// Check if URL already exists
	existingCode, err := s.postgresRepo.GetURLByOriginalURL(originalURL)
	if err == nil {
		return &model.CreateResponse{
			ShortURL:    fmt.Sprintf("%s/%s", s.baseURL, existingCode),
			OriginalURL: originalURL,
			CreatedAt:   time.Now(),
		}, nil
	}

	// Generate unique short code
	hash := md5.Sum([]byte(originalURL + time.Now().String()))
	hashStr := hex.EncodeToString(hash[:])
	hashNum := uint64(0)
	for _, char := range hashStr[:8] {
		hashNum = hashNum*256 + uint64(char)
	}
	shortCode := utils.Base62Encode(hashNum)

	// Save to database
	if err := s.postgresRepo.CreateURL(shortCode, originalURL); err != nil {
		return nil, fmt.Errorf("failed to create URL: %v", err)
	}

	// Cache in Redis
	if err := s.redisRepo.SetURL(shortCode, originalURL, 24*time.Hour); err != nil {
		fmt.Printf("Warning: Failed to cache URL: %v\n", err)
	}

	return &model.CreateResponse{
		ShortURL:    fmt.Sprintf("%s/%s", s.baseURL, shortCode),
		OriginalURL: originalURL,
		CreatedAt:   time.Now(),
	}, nil
}

func (s *URLService) Redirect(shortCode string) (string, error) {
	// Try cache first
	originalURL, err := s.redisRepo.GetURL(shortCode)
	if err == nil {
		// Update click count in background
		go s.postgresRepo.IncrementClickCount(shortCode)
		return originalURL, nil
	}

	// Fallback to database
	originalURL, err = s.postgresRepo.GetURLByShortCode(shortCode)
	if err != nil {
		return "", fmt.Errorf("URL not found")
	}

	// Cache the result
	go s.redisRepo.SetURL(shortCode, originalURL, 24*time.Hour)

	// Update click count
	go s.postgresRepo.IncrementClickCount(shortCode)

	return originalURL, nil
}
