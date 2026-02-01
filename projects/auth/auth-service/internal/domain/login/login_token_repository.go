package login

type LoginTokenRepository interface {
	Save(token *Token)
	Find(value string) (*Token, error)
}
