package dtos

type AuthorizationResponse struct {
	RedirectURI string
	Code        string
	State       string
}
