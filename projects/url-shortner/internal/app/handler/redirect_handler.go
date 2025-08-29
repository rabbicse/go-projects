package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/model"
	"github.com/rabbicse/go-projects/projects/url-shortner/internal/app/service"
)

type RedirectHandler struct {
	service *service.RedirectService
}

func NewRedirectHandler(service *service.RedirectService) *RedirectHandler {
	return &RedirectHandler{
		service: service,
	}
}

func (handler *RedirectHandler) Redirect(ctx *fiber.Ctx) error {
	shortCode := ctx.Params("code")
	if shortCode == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(model.ErrorResponse{
			Error: "Short code is required",
		})
	}

	originalURL, err := handler.service.Redirect(shortCode)
	if err != nil {
		return ctx.Status(fiber.StatusNotFound).JSON(model.ErrorResponse{
			Error: "URL not found",
		})
	}

	return ctx.Redirect(originalURL, fiber.StatusMovedPermanently)
}
