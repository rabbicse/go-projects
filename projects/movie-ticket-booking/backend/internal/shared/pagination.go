package shared

// Pagination holds offset-based pagination parameters.
type Pagination struct {
	Page     int
	PageSize int
}

func (p Pagination) Offset() int {
	if p.Page < 1 {
		return 0
	}
	return (p.Page - 1) * p.PageSize
}

func (p Pagination) Limit() int {
	if p.PageSize < 1 {
		return 20
	}
	return p.PageSize
}
