package client

import "slices"

type Client struct {
	ID           string
	SecretHash   string
	RedirectURIs []string
	Scopes       []string
	GrantTypes   []GrantType
	IsPublic     bool
}

func (c *Client) AllowsRedirect(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

func (c *Client) AllowsScope(scope string) bool {
	return slices.Contains(c.Scopes, scope)
}

func (c *Client) SupportsGrant(grant GrantType) bool {

	for _, g := range c.GrantTypes {
		if g == grant {
			return true
		}
	}

	return false
}
