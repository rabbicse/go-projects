package handlers

import "github.com/gin-gonic/gin"

func ProtectedResource(c *gin.Context) {
	sub, _ := c.Get("sub")
	scope, _ := c.Get("scope")

	c.JSON(200, gin.H{
		"message": "protected resource accessed",
		"user":    sub,
		"scope":   scope,
	})
}
