package models

import "time"

type Media struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	FileName   string    `json:"file_name"`
	FilePath   string    `json:"file_path"`
	MimeType   string    `json:"mime_type"`
	Size       int64     `json:"size"`
	UploadedAt time.Time `json:"uploaded_at"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type StreamRequest struct {
	MediaID string `json:"media_id"`
	Quality string `json:"quality,omitempty"`
}