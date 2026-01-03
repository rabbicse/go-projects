package valueobjects

import (
	"errors"
	"strings"
)

type Scope struct {
	Name        string
	Description string
}

// func NewScope(name, description string) *Scope {
// 	return &Scope{
// 		Name:        name,
// 		Description: description,
// 	}
// }

func NewScope(value string) (*Scope, error) {
	if value == "" {
		return &Scope{}, errors.New("scope cannot be empty")
	}

	// Basic validation (extend based on requirements)
	if strings.Contains(value, " ") {
		return &Scope{}, errors.New("scope cannot contain spaces")
	}

	return &Scope{Name: value}, nil
}

func (s Scope) Value() string {
	return s.Name
}

func (s Scope) Equals(other Scope) bool {
	return s.Name == other.Name
}
