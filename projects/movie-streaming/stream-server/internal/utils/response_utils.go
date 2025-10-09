package utils

import (
	"magicstream/internal/models"

	"github.com/gofiber/fiber/v2"
)

// SuccessResponse returns a successful API response
func SuccessResponse(c *fiber.Ctx, message string, data interface{}) error {
	return c.JSON(models.APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// ErrorResponse returns an error API response
func ErrorResponse(c *fiber.Ctx, statusCode int, message string, err error) error {
	errorMsg := ""
	if err != nil {
		errorMsg = err.Error()
	}

	return c.Status(statusCode).JSON(models.APIResponse{
		Success: false,
		Message: message,
		Error:   errorMsg,
	})
}
