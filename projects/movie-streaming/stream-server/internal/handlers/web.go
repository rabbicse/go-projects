package handlers

import (
	"github.com/gofiber/fiber/v2"
)

// IndexHandler renders the main page
func IndexHandler(c *fiber.Ctx) error {
	return c.Render("index", fiber.Map{
		"Title": "MagicStream - Media Streaming Server",
	})
}

// PlayerHandler renders the media player page
func PlayerHandler(c *fiber.Ctx) error {
	id := c.Params("id")

	media, err := services.GetMediaByID(id)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("Media not found")
	}

	return c.Render("player", fiber.Map{
		"Title": media.Title,
		"Media": media,
	})
}
