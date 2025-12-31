package valueobjects

type RedirectURI struct {
	URI string
}

func NewRedirectURI(uri string) *RedirectURI {
	return &RedirectURI{
		URI: uri,
	}
}
