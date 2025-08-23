package model

import (
	"time"

	"gorm.io/gorm"
)

type URL struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	ShortCode   string    `gorm:"uniqueIndex;size:15;not null" json:"short_code"`
	OriginalURL string    `gorm:"type:text;not null" json:"original_url"`
	CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`
	ClickCount  uint64    `gorm:"default:0" json:"click_count"`
}

type CreateRequest struct {
	URL string `json:"url" validate:"required,url"`
}

type CreateResponse struct {
	ShortURL    string    `json:"short_url"`
	OriginalURL string    `json:"original_url"`
	CreatedAt   time.Time `json:"created_at"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// Add this function for auto migration
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&URL{})
}
