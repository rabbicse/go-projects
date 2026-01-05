package oauth

type AuthorizeRequest struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
	UserID       string // already authenticated user
}

type AuthorizeResponse struct {
	RedirectURI string
	Code        string
	State       string
}

type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
}

type TokenResponse struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
	Scope        string
	IDToken      string // OIDC (added later)
}
