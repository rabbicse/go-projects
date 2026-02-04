package main

import (
	"github.com/gin-gonic/gin"
	"github.com/rabbicse/resource-service/internal/application/token"
	"github.com/rabbicse/resource-service/internal/handlers"
	"github.com/rabbicse/resource-service/internal/middleware"
)

func main() {
	r := gin.Default()

	validator := &token.TokenValidator{
		IntrospectionURL: "http://localhost:8080/oauth/introspect",
		ClientID:         "resource-server",
		ClientSecret:     "secret",
	}

	r.GET(
		"/protected",
		middleware.AuthorizationMiddleware(validator),
		handlers.ProtectedResource,
	)

	r.Run(":9090")
}
