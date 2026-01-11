package common

import "errors"

var (
	ErrNotFound        = errors.New("not found")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrInvalidClient   = errors.New("invalid client")
	ErrInvalidGrant    = errors.New("invalid grant")
	ErrInvalidRedirect = errors.New("invalid redirect uri")
	ErrExpired         = errors.New("expired")
	ErrInvalidScope    = errors.New("invalid scope")

	ErrInvalidProof = errors.New("invalid proof")

	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidLogin       = errors.New("invalid login")
	ErrInvalidLoginToken  = errors.New("invalid login token")
)
