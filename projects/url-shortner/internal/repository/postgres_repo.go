package repository

import (
	"fmt"
	"time"

	"github.com/rabbicse/go-projects/projects/url-shortner/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type PostgresRepo struct {
	db *gorm.DB
}

func NewPostgresRepo(host, port, user, password, dbname, sslmode string) (*PostgresRepo, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// Get underlying sql.DB for connection pool settings
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %v", err)
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	// Auto migrate the schema
	if err := db.AutoMigrate(&model.URL{}); err != nil {
		return nil, fmt.Errorf("failed to auto migrate: %v", err)
	}

	return &PostgresRepo{db: db}, nil
}

func (r *PostgresRepo) CreateURL(shortCode, originalURL string) error {
	url := &model.URL{
		ShortCode:   shortCode,
		OriginalURL: originalURL,
	}

	result := r.db.Create(url)
	return result.Error
}

func (r *PostgresRepo) GetURLByShortCode(shortCode string) (string, error) {
	var url model.URL
	result := r.db.Where("short_code = ?", shortCode).First(&url)
	if result.Error != nil {
		return "", result.Error
	}
	return url.OriginalURL, nil
}

func (r *PostgresRepo) GetURLByOriginalURL(originalURL string) (string, error) {
	var url model.URL
	result := r.db.Where("original_url = ?", originalURL).First(&url)
	if result.Error != nil {
		return "", result.Error
	}
	return url.ShortCode, nil
}

func (r *PostgresRepo) IncrementClickCount(shortCode string) error {
	result := r.db.Model(&model.URL{}).
		Where("short_code = ?", shortCode).
		Update("click_count", gorm.Expr("click_count + 1"))
	return result.Error
}

func (r *PostgresRepo) Close() error {
	sqlDB, err := r.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Additional useful methods with GORM
func (r *PostgresRepo) GetURLWithStats(shortCode string) (*model.URL, error) {
	var url model.URL
	result := r.db.Where("short_code = ?", shortCode).First(&url)
	return &url, result.Error
}

func (r *PostgresRepo) GetTopURLs(limit int) ([]model.URL, error) {
	var urls []model.URL
	result := r.db.Order("click_count DESC").Limit(limit).Find(&urls)
	return urls, result.Error
}

func (r *PostgresRepo) DeleteURL(shortCode string) error {
	result := r.db.Where("short_code = ?", shortCode).Delete(&model.URL{})
	return result.Error
}

func (r *PostgresRepo) URLExists(shortCode string) (bool, error) {
	var count int64
	result := r.db.Model(&model.URL{}).Where("short_code = ?", shortCode).Count(&count)
	if result.Error != nil {
		return false, result.Error
	}
	return count > 0, nil
}
