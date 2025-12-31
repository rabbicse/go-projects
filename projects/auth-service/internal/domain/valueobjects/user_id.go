package valueobjects

type UserID struct {
	value string
}

func NewUserID(value string) UserID {
	return UserID{value: value}
}
