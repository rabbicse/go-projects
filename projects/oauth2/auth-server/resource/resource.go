// Package resource provides a tiny protected resource endpoint used by the
// example auth-server. It validates access tokens issued by the `auth`
// package and returns protected data for the associated client. This is a
// demonstration-only resource server and does not implement real token
// verification or security checks.
package resource

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/rabbicse/go-projects/oauth2/auth-server/auth"
)

func GrantAccess(c *fiber.Ctx) error {

	tokenStr := c.Query("access_token")

	token, err := strconv.Atoi(tokenStr)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).
			SendString("Unauthorized")
	}

	for clientId, combo := range auth.AccessCombinations {
		if combo.AccessToken == token {
			data := secretData[clientId]
			return c.SendString(data)
		}
	}

	return c.Status(fiber.StatusUnauthorized).
		SendString("Unauthorized")
}
