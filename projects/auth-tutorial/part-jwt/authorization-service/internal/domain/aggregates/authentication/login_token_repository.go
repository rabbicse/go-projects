package authentication

type LoginTokenRepository interface {
	Save(*LoginToken)
	Find(string) (*LoginToken, error)
	MarkUsed(string)
}
