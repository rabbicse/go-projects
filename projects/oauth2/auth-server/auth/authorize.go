package auth

import (
	"fmt"
	"slices"

	"github.com/gofiber/fiber/v2"
)

// Authorize handles OAuth2 authorization requests
func Authorize(c *fiber.Ctx) error {
	// 1. Validate HTTP Method
	if c.Method() != fiber.MethodGet {
		return c.Status(fiber.StatusMethodNotAllowed).
			SendString("Invalid Method")
	}

	// 2. Validate request parameters
	params := c.Queries()
	if !validAuthRequest(params) {
		return c.Status(fiber.StatusUnauthorized).
			SendString("Unauthorized")
	}

	// 3. Create Access Combination
	clientID := params["client_id"]
	state := params["state"]

	combo := NewAccessCombination(state)
	AccessCombinations[ClientId(clientID)] = *combo

	// 4. Request user permission (login / consent)
	return requestUserPermission(c)
}

func validAuthRequest(params map[string]string) bool {
	responseType := params["response_type"]
	clientId := ClientId(params["client_id"])
	redirectUri := params["redirect_uri"]
	scope := params["scope"]

	if app, exists := apps[clientId]; exists &&
		app.RedirectUri == redirectUri &&
		responseType == "code" &&
		slices.Contains(app.Scope, scope) {
		return true
	}

	return false
}

func requestUserPermission(c *fiber.Ctx) error {
	clientId := c.Query("client_id")
	redirectUri := c.Query("redirect_uri")
	scope := c.Query("scope")
	state := c.Query("state")

	url := fmt.Sprintf(
		"%s/login?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		ServerUrl, clientId, redirectUri, scope, state,
	)

	return c.Redirect(url, fiber.StatusTemporaryRedirect)
}
