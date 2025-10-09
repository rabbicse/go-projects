package services

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"magicstream/internal/config"
	"magicstream/internal/models"
	"mime"
	"os"
	"path/filepath"
	"time"

	"github.com/gofiber/fiber/v2"
)

var mediaStore = make(map[string]*models.Media)
var cfg = config.Load()

// GetAllMedia returns all media files
func GetAllMedia() ([]*models.Media, error) {
	var mediaList []*models.Media
	for _, media := range mediaStore {
		mediaList = append(mediaList, media)
	}
	return mediaList, nil
}

// GetMediaByID returns a media file by ID
func GetMediaByID(id string) (*models.Media, error) {
	media, exists := mediaStore[id]
	if !exists {
		return nil, fmt.Errorf("media not found: %s", id)
	}
	return media, nil
}

// ProcessUploadedFile handles file upload and processing
func ProcessUploadedFile(file *fiber.FormFile) (*models.Media, error) {
	// Open uploaded file
	src, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer src.Close()

	// Generate unique file ID
	hash := md5.New()
	hash.Write([]byte(file.Filename + time.Now().String()))
	fileID := hex.EncodeToString(hash.Sum(nil))

	// Create file path
	fileExt := filepath.Ext(file.Filename)
	newFileName := fileID + fileExt
	filePath := filepath.Join(cfg.UploadPath, newFileName)

	// Create destination file
	dst, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}
	defer dst.Close()

	// Copy file content
	if _, err = io.Copy(dst, src); err != nil {
		return nil, err
	}

	// Get MIME type
	mimeType := mime.TypeByExtension(fileExt)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	// Create media object
	media := &models.Media{
		ID:         fileID,
		Title:      file.Filename,
		FileName:   newFileName,
		FilePath:   cfg.UploadPath,
		MimeType:   mimeType,
		Size:       file.Size,
		UploadedAt: time.Now(),
	}

	// Store in memory (in production, use database)
	mediaStore[fileID] = media

	return media, nil
}

// DeleteMediaByID removes a media file
func DeleteMediaByID(id string) error {
	media, exists := mediaStore[id]
	if !exists {
		return fmt.Errorf("media not found: %s", id)
	}

	// Remove file from filesystem
	filePath := filepath.Join(media.FilePath, media.FileName)
	if err := os.Remove(filePath); err != nil {
		return err
	}

	// Remove from storage
	delete(mediaStore, id)

	return nil
}
