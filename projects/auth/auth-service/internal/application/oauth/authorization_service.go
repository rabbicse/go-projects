package oauth

import "context"

// AuthorizationService handles RFC 6749 §4.1 (A)(B)(C)
type AuthorizationService interface {
	Authorize(
		ctx context.Context,
		req AuthorizeRequest,
	) (*AuthorizeResponse, error)
}
