package token

type TokenRepository interface {
	Save(token *Token) error
	FindByAccessToken(token string) (*Token, error)
	Revoke(token string) error
}
