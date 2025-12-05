package resource

import "github.com/rabbicse/go-projects/oauth2/auth-server/auth"

var secretData = map[auth.ClientId]string{
	"printshop": "super secret photos",
}
