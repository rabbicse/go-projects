package oauth

type AuthorizationCodeRepository interface {
	Save(code *AuthorizationCode) error
	Get(code string) (*AuthorizationCode, error)
	// 🔥 Atomic operation
	Consume(code string) (*AuthorizationCode, error)
}
