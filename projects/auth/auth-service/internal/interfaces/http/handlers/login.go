package handlers

import (
	"encoding/base64"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/application/auth"
)

type LoginHandler struct {
	svc *auth.LoginService
}

func (h *LoginHandler) Start(c *gin.Context) {
	var req struct{ Username string }
	c.BindJSON(&req)

	chal, salt, err := h.svc.Start(req.Username)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid user"})
		return
	}

	c.JSON(200, gin.H{
		"challenge_id": chal.ID,
		"challenge":    base64.RawURLEncoding.EncodeToString(chal.Value),
		"salt":         base64.RawURLEncoding.EncodeToString(salt),
	})
}

func (h *LoginHandler) Verify(c *gin.Context) {
	var req struct {
		Username    string
		ChallengeID string
		Proof       string
	}
	c.BindJSON(&req)

	proof, _ := base64.RawURLEncoding.DecodeString(req.Proof)

	loginToken, err := h.svc.Verify(req.Username, req.ChallengeID, proof)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid login"})
		return
	}

	c.JSON(200, gin.H{"login_token": loginToken})
}
