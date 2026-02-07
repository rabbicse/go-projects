package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JWKSHandler struct {
	set jwk.Set
}

func NewJWKSHandler(set jwk.Set) *JWKSHandler {
	return &JWKSHandler{set: set}
}

func (h *JWKSHandler) Handle(c *gin.Context) {

	// VERY IMPORTANT — caching
	c.Header(
		"Cache-Control",
		"public, max-age=86400",
	)

	c.Header(
		"Content-Type",
		"application/json",
	)

	jsonBytes, err := json.Marshal(h.set)
	if err != nil {

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to marshal jwks",
		})

		return
	}

	c.Data(
		http.StatusOK,
		"application/json",
		jsonBytes,
	)
}
