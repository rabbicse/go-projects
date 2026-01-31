package dtos

type IntrospectionResponse struct {
	Active   bool   `json:"active"`
	Sub      string `json:"sub,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
}
