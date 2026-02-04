package client

type ClientRepository interface {
	FindByID(id string) (*Client, error)
}
