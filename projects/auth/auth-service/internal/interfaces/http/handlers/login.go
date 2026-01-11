package handlers

import (
	"encoding/base64"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/application/auth"
)

type LoginHandler struct {
	svc *auth.LoginService
}

func NewLoginHandler(svc *auth.LoginService) *LoginHandler {
	return &LoginHandler{svc}
}

func (h *LoginHandler) Start(c *gin.Context) {
	log.Println("LOGIN HANDLER START CALLED")

	var req struct {
		Username string `json:"username"`
	}
	if err := c.BindJSON(&req); err != nil {
		log.Println("BIND ERROR:", err)
		c.JSON(400, gin.H{"error": "bad request"})
		return
	}

	log.Println("USERNAME RECEIVED:", req.Username)

	chal, salt, err := h.svc.Start(req.Username)
	if err != nil {
		log.Println("LOGIN SERVICE START FAILED:", err)
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
	log.Println("LOGIN VERIFY HANDLER CALLED")

	var req struct {
		Username    string `json:"username"`
		ChallengeID string `json:"challenge_id"`
		Proof       string `json:"proof"`
	}

	if err := c.BindJSON(&req); err != nil {
		log.Println("BIND ERROR:", err)
		c.JSON(400, gin.H{"error": "bad request"})
		return
	}

	log.Printf("REQUEST: %+v\n", req)

	proof, err := base64.RawURLEncoding.DecodeString(req.Proof)
	if err != nil {
		log.Println("PROOF BASE64 DECODE FAILED:", err)
		c.JSON(400, gin.H{"error": "invalid proof encoding"})
		return
	}

	loginToken, err := h.svc.Verify(req.Username, req.ChallengeID, proof)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid login"})
		return
	}

	c.JSON(200, gin.H{"login_token": loginToken})
}
