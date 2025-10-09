package handlers

import (
	"path/filepath"

	"github.com/gofiber/fiber/v2"
)

// GetMediaList returns list of all media files
func GetMediaList(c *fiber.Ctx) error {
	mediaList, err := services.GetAllMedia()
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, "Failed to get media list", err)
	}

	return utils.SuccessResponse(c, "Media list retrieved successfully", mediaList)
}

// UploadMedia handles file uploads
func UploadMedia(c *fiber.Ctx) error {
	// Get uploaded file
	file, err := c.FormFile("file")
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusBadRequest, "No file uploaded", err)
	}

	// Save and process the file
	media, err := services.ProcessUploadedFile(file)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, "Failed to process file", err)
	}

	return utils.SuccessResponse(c, "File uploaded successfully", media)
}

// GetMediaInfo returns information about a specific media file
func GetMediaInfo(c *fiber.Ctx) error {
	id := c.Params("id")

	media, err := services.GetMediaByID(id)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusNotFound, "Media not found", err)
	}

	return utils.SuccessResponse(c, "Media info retrieved successfully", media)
}

// DeleteMedia removes a media file
func DeleteMedia(c *fiber.Ctx) error {
	id := c.Params("id")

	if err := services.DeleteMediaByID(id); err != nil {
		return utils.ErrorResponse(c, fiber.StatusInternalServerError, "Failed to delete media", err)
	}

	return utils.SuccessResponse(c, "Media deleted successfully", nil)
}

// StreamMedia streams a media file
func StreamMedia(c *fiber.Ctx) error {
	id := c.Params("id")

	media, err := services.GetMediaByID(id)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusNotFound, "Media not found", err)
	}

	filePath := filepath.Join(media.FilePath, media.FileName)

	// Set appropriate headers for streaming
	c.Set("Content-Type", media.MimeType)
	c.Set("Accept-Ranges", "bytes")

	return c.SendFile(filePath, false)
}

// StreamMediaFile streams a specific media file with filename
func StreamMediaFile(c *fiber.Ctx) error {
	id := c.Params("id")
	filename := c.Params("filename")

	media, err := services.GetMediaByID(id)
	if err != nil {
		return utils.ErrorResponse(c, fiber.StatusNotFound, "Media not found", err)
	}

	// Verify filename matches
	if media.FileName != filename {
		return utils.ErrorResponse(c, fiber.StatusNotFound, "File not found", nil)
	}

	filePath := filepath.Join(media.FilePath, media.FileName)

	// Set appropriate headers for streaming
	c.Set("Content-Type", media.MimeType)
	c.Set("Accept-Ranges", "bytes")

	return c.SendFile(filePath, false)
}
