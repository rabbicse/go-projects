package auth

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

func RequestApproval(c *fiber.Ctx) error {

	if c.Method() != fiber.MethodPost {
		return c.Status(fiber.StatusMethodNotAllowed).
			SendString("Invalid Method")
	}

	if clientId, ok := validRequestApproval(c); ok {
		return sendCode(c, clientId)
	}

	return c.Status(fiber.StatusUnauthorized).
		SendString("Unauthorized")
}

func validRequestApproval(c *fiber.Ctx) (ClientId, bool) {

	action := c.FormValue("action")
	state := c.FormValue("state")
	clientId := ClientId(c.FormValue("client_id"))

	fmt.Printf("RequestApproval: action = %s, state = %s, clientId = %s\n", action, state, clientId)

	storedState := AccessCombinations[clientId].State

	if action == "allow" && state == storedState {
		return clientId, true
	}

	return clientId, false
}

func sendCode(c *fiber.Ctx, clientId ClientId) error {

	code := AccessCombinations[clientId].Code
	redirectUrl := apps[clientId].RedirectUri
	state := c.FormValue("state")

	url := fmt.Sprintf(
		"%s?code=%d&state=%s",
		redirectUrl, code, state,
	)

	return c.Redirect(url, fiber.StatusTemporaryRedirect)
}
