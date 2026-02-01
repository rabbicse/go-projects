package dtos

type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub"`
	Scope     string `json:"scope"`
	ClientID  string `json:"client_id"`
	ExpiresAt int64  `json:"exp"`
}
