// internal/interfaces/http/handlers/mfa_handler.go
package handlers

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/rabbicse/auth-service/internal/application/auth"
	"github.com/rabbicse/auth-service/internal/domain/login"
)

type MFAHandler struct {
	mfaService        *auth.MFAService
	loginTokenRepo    login.LoginTokenRepository
	loginTokenService *auth.LoginTokenService
}

func NewMFAHandler(
	mfaService *auth.MFAService,
	loginTokenRepo login.LoginTokenRepository,
	loginTokenService *auth.LoginTokenService,
) *MFAHandler {
	return &MFAHandler{mfaService, loginTokenRepo, loginTokenService}
}

// POST /mfa/enroll/start
func (h *MFAHandler) StartEnroll(c *gin.Context) {
	loginToken, err := ExtractLoginToken(c)
	log.Println("MFA StartEnroll login_token:", loginToken)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	token, err := h.loginTokenRepo.Find(loginToken)
	if err != nil {
		log.Println("MFA token lookup failed:", err)
		c.JSON(401, gin.H{"error": "invalid login token"})
		return
	}

	log.Println("MFA userID:", token.UserID)

	secret, qr, err := h.mfaService.StartEnrollment(token.UserID)
	if err != nil {
		log.Println("MFA start enrollment error:", err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"secret": secret,
		"qr_url": qr,
	})
}

// POST /mfa/enroll/verify
func (h *MFAHandler) VerifyEnroll(c *gin.Context) {
	loginToken, err := ExtractLoginToken(c)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	token, err := h.loginTokenRepo.Find(loginToken)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid login token"})
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	c.BindJSON(&req)

	if err := h.mfaService.VerifyEnrollment(token.UserID, req.Code); err != nil {
		c.JSON(401, gin.H{"error": "invalid code"})
		return
	}

	c.JSON(200, gin.H{"status": "mfa enabled"})
}

// POST /mfa/verify (during login)
func (h *MFAHandler) VerifyLogin(c *gin.Context) {
	loginToken, err := ExtractLoginToken(c)
	if err != nil {
		c.JSON(401, gin.H{"error": err.Error()})
		return
	}

	token, err := h.loginTokenRepo.Find(loginToken)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid login token"})
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	c.BindJSON(&req)

	if err := h.mfaService.VerifyLogin(token.UserID, req.Code); err != nil {
		c.JSON(401, gin.H{"error": "invalid mfa"})
		return
	}

	h.loginTokenService.UpgradeToMFA(loginToken)
	c.JSON(200, gin.H{"status": "mfa verified"})
}
