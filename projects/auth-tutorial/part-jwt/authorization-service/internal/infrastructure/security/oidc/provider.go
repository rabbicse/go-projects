package oidc

type OidcProvider struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	ResponseTypes         []string `json:"response_types_supported"`
	SubjectTypes          []string `json:"subject_types_supported"`
	IDTokenAlgs           []string `json:"id_token_signing_alg_values_supported"`
	Scopes                []string `json:"scopes_supported"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported"`
}

func NewOidcProvider(issuer string) *OidcProvider {

	return &OidcProvider{
		Issuer: issuer,

		AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint:         issuer + "/token",
		JWKSUri:               issuer + "/.well-known/jwks.json",

		ResponseTypes: []string{
			"code",
		},

		SubjectTypes: []string{
			"public",
		},

		IDTokenAlgs: []string{
			"RS256",
		},

		Scopes: []string{
			"openid",
			"profile",
			"email",
		},

		TokenAuthMethods: []string{
			"client_secret_basic",
		},
	}
}
