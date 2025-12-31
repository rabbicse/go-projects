package valueobjects

type ClientID struct {
	ID string
}

func NewClientID(id string) *ClientID {
	return &ClientID{
		ID: id,
	}
}
