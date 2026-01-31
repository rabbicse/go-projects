package authentication

type LoginChallengeRepository interface {
	Save(*LoginChallenge) error
	Find(string) (*LoginChallenge, error)
	MarkUsed(string) error
}
