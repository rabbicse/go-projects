package user

type User struct {
	ID         string
	Username   string
	Email      string
	Password   string
	IsVerified bool

	Salt             []byte
	PasswordVerifier []byte // Argon2(password, salt)

	MFAEnabled bool
	MFASecret  string // base32 TOTP secret
}
