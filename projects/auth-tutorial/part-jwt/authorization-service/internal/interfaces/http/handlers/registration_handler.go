package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/application/authentication"
	"github.com/rabbicse/auth-service/internal/interfaces/http/dtos"
)

type RegisterHandler struct {
	svc *authentication.UserRegistrationService
}

func NewRegisterHandler(svc *authentication.UserRegistrationService) *RegisterHandler {
	return &RegisterHandler{svc: svc}
}

func (h *RegisterHandler) Register(c *gin.Context) {
	var req dtos.UserRegistrationRequest

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	u, err := h.svc.Register(req.Username, req.Email, req.Salt, req.Verifier)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":       u.ID,
		"username": u.Username,
	})
}
