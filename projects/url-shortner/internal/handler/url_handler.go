package handler

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/model"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/service"
)

type URLHandler struct {
	service *service.URLService
}

func NewURLHandler(service *service.URLService) *URLHandler {
	return &URLHandler{service: service}
}

func (h *URLHandler) CreateShortURL(c *fiber.Ctx) error {
	var req model.CreateRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(model.ErrorResponse{
			Error: "Invalid request body",
		})
	}

	if req.URL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(model.ErrorResponse{
			Error: "URL is required",
		})
	}

	response, err := h.service.CreateShortURL(req.URL)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(model.ErrorResponse{
			Error: "Failed to create short URL",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response)
}

func (h *URLHandler) Redirect(c *fiber.Ctx) error {
	shortCode := c.Params("code")
	if shortCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(model.ErrorResponse{
			Error: "Short code is required",
		})
	}

	originalURL, err := h.service.Redirect(shortCode)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(model.ErrorResponse{
			Error: "URL not found",
		})
	}

	return c.Redirect(originalURL, fiber.StatusMovedPermanently)
}

func (h *URLHandler) HealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":    "healthy",
		"timestamp": time.Now(),
	})
}
