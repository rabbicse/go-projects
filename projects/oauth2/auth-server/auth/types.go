// Package auth implements a minimal OAuth2-style authorization server
// used by the example auth-server in this repository. It contains simple
// in-memory client configuration, helpers to create temporary authorization
// codes and access tokens, and types used by the HTTP handlers in the
// `auth` package. This package is intentionally small and intended for
// learning/demo purposes — it is not secure or production-ready.
package auth

import "math/rand"

const (
	Port      = ":8080"
	ServerUrl = "http://localhost:8080"
)

type ClientId string

type App struct {
	ClientId     ClientId
	ClientSecret string
	RedirectUri  string
	Scope        []string
}

type AccessCombination struct {
	State       string
	Code        int
	AccessToken int
}

func NewAccessCombination(state string) *AccessCombination {
	return &AccessCombination{
		State:       state,
		Code:        rand.Int(),
		AccessToken: rand.Int(),
	}
}
