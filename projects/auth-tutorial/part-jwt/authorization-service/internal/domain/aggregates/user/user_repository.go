package user

type UserRepository interface {
	FindByID(id string) (*User, error)
	FindByEmail(email string) (*User, error)
	FindByUsername(username string) (*User, error)
	Save(u *User) error
}
