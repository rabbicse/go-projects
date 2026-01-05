package handlers

import "github.com/gin-gonic/gin"

type OIDCHandler struct {
	issuer string
}

func NewOIDCHandler(issuer string) *OIDCHandler {
	return &OIDCHandler{issuer: issuer}
}

func (h *OIDCHandler) Discovery(c *gin.Context) {
	c.JSON(200, gin.H{
		"issuer":                                h.issuer,
		"authorization_endpoint":                h.issuer + "/authorize",
		"token_endpoint":                        h.issuer + "/token",
		"jwks_uri":                              h.issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
	})
}
