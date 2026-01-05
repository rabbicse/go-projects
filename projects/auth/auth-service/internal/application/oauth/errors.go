package oauth

import "errors"

var (
	ErrUnsupportedResponseType = errors.New("unsupported response type")
	ErrInvalidClient           = errors.New("invalid client")
	ErrInvalidRedirectURI      = errors.New("invalid redirect uri")
	ErrInvalidScope            = errors.New("invalid scope")

	ErrUnsupportedGrantType = errors.New("unsupported grant type")
	ErrInvalidAuthCode      = errors.New("invalid authorization code")
	ErrClientAuthFailed     = errors.New("client authentication failed")
)
