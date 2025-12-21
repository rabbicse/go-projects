package auth

import (
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func GetAccessToken(c *fiber.Ctx) error {

	if c.Method() != fiber.MethodPost {
		return c.SendStatus(fiber.StatusMethodNotAllowed)
	}

	if clientId, ok := validCodeRequest(c); ok {
		return grantAccessToken(c, clientId)
	}

	return c.SendStatus(fiber.StatusUnauthorized)
}

func validCodeRequest(c *fiber.Ctx) (ClientId, bool) {

	form := c.Request().PostArgs()

	grantType := string(form.Peek("grant_type"))
	codeStr := string(form.Peek("code"))
	redirectUri := string(form.Peek("redirect_uri"))

	code, err := strconv.Atoi(codeStr)
	if err != nil {
		return "", false
	}

	// Parse Basic Auth header
	clientIdStr, clientSecret, ok := ParseBasicAuth(c.Get("Authorization"))
	clientId := ClientId(clientIdStr)
	if !ok {
		return clientId, false
	}

	app, appExists := apps[clientId]
	accessCombo, comboExists := AccessCombinations[clientId]

	if appExists &&
		comboExists &&
		grantType == "authorization_code" &&
		redirectUri == app.RedirectUri &&
		code == accessCombo.Code &&
		clientSecret == app.ClientSecret {
		return clientId, true
	}

	return clientId, false
}

func grantAccessToken(c *fiber.Ctx, clientId ClientId) error {

	accessToken := strconv.Itoa(AccessCombinations[clientId].AccessToken)

	return c.JSON(fiber.Map{
		"access_token": accessToken,
		"token_type":   "example",
	})
}

func ParseBasicAuth(header string) (username, password string, ok bool) {
	if header == "" || !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}

	payload, err := base64.StdEncoding.DecodeString(
		strings.TrimPrefix(header, "Basic "),
	)
	if err != nil {
		return "", "", false
	}

	parts := strings.SplitN(string(payload), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	return parts[0], parts[1], true
}
