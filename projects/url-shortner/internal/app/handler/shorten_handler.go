package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/model"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/service"
)

type ShortenHandler struct {
	service *service.ShortenerService
}

func NewShortenHandler(service *service.ShortenerService) *ShortenHandler {
	return &ShortenHandler{service: service}
}

func (handler *ShortenHandler) CreateShortURL(ctx *fiber.Ctx) error {
	var req model.CreateRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(model.ErrorResponse{
			Error: "Invalid request body",
		})
	}

	if req.URL == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(model.ErrorResponse{
			Error: "URL is required",
		})
	}

	response, err := handler.service.ShortenURL(req.URL)
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(model.ErrorResponse{
			Error: "Failed to create short URL",
		})
	}

	return ctx.Status(fiber.StatusCreated).JSON(response)
}
