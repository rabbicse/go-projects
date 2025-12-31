package valueobjects

type Scope struct {
	Name        string
	Description string
}

func NewScope(name, description string) *Scope {
	return &Scope{
		Name:        name,
		Description: description,
	}
}
