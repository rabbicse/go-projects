package dtos

type UserRegistrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Salt     string `json:"salt"`
	Verifier string `json:"verifier"`
}
