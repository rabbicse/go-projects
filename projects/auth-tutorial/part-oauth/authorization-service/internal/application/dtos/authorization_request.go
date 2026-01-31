package dtos

type AuthorizationRequest struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
	UserID       string // already authenticated user
}
