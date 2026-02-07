package valueobjects

import "github.com/golang-jwt/jwt/v5"

// type AccessClaims struct {
// 	Sub      string   `json:"sub"`             // user ID or client_id
// 	Scope    string   `json:"scope"`           // space-separated or comma
// 	Roles    []string `json:"roles,omitempty"` // if you have them
// 	ClientID string   `json:"client_id,omitempty"`
// 	Jti      string   `json:"jti,omitempty"` // optional unique id
// 	jwt.RegisteredClaims
// }

type AccessClaims struct {
	Scope    string   `json:"scope"`
	Roles    []string `json:"roles,omitempty"`
	ClientID string   `json:"client_id,omitempty"`

	jwt.RegisteredClaims
}
