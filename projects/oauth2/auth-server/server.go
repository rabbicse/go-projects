package main

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/rabbicse/go-projects/oauth2/auth-server/auth"
	"github.com/rabbicse/go-projects/oauth2/auth-server/resource"
)

const (
	Port      = ":8080"
	ServerUrl = "http://localhost:8080"
)

func main() {
	app := fiber.New()

	app.Get("/authorize", auth.Authorize)
	app.Get("/access", resource.GrantAccess)

	app.Post("/login", Login)
	app.Post("/consent", auth.RequestApproval)
	app.Post("/token", auth.GetAccessToken)

	log.Fatal(app.Listen(Port))
}

func Login(c *fiber.Ctx) error {
	clientId := c.Query("client_id")
	redirectUri := c.Query("redirect_uri")
	scope := c.Query("scope")
	state := c.Query("state")

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<title>Photo Gallery</title>
</head>
<body style="background-color: blue;">
	<h1>Photo Gallery</h1>
	<p>Print Service is requesting access to your photos.</p>
	<form method="post" action="/consent">
		<input type="hidden" name="client_id" value="%s">
		<input type="hidden" name="redirect_uri" value="%s">
		<input type="hidden" name="scope" value="%s">
		<input type="hidden" name="state" value="%s">
		<button type="submit" name="action" value="allow">Allow</button>
	</form>
</body>
</html>
`, clientId, redirectUri, scope, state)

	return c.Type("html").SendString(html)
}
