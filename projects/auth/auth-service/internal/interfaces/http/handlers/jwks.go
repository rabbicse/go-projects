package handlers

import (
	"github.com/gin-gonic/gin"
	jwtinfra "github.com/rabbicse/auth-service/internal/infrastructure/jwt"
)

type JWKSHandler struct {
	jwk jwtinfra.JWK
}

func NewJWKSHandler(jwk jwtinfra.JWK) *JWKSHandler {
	return &JWKSHandler{jwk: jwk}
}

func (h *JWKSHandler) Handle(c *gin.Context) {
	c.JSON(200, gin.H{
		"keys": []jwtinfra.JWK{h.jwk},
	})
}
