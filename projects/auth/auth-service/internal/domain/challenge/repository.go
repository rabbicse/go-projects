package challenge

type Repository interface {
	Save(*Challenge)
	Find(string) (*Challenge, error)
	MarkUsed(string)
}
