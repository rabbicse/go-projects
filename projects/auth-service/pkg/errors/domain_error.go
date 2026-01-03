package errors

import "fmt"

// DomainError represents domain-specific errors
type DomainError struct {
	Code    string `json:"error"`
	Message string `json:"error_description"`
	Cause   error  `json:"-"`
}

func (e *DomainError) Error() string {
	return e.Code + ": " + e.Message
}

func NewDomainError(code, message string, args ...interface{}) *DomainError {
	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}
	return &DomainError{
		Code:    code,
		Message: message,
	}
}

func WrapDomainError(err error, code, message string) *DomainError {
	return &DomainError{
		Code:    code,
		Message: message,
		Cause:   err,
	}
}
