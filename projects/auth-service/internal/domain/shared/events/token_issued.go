package events

import "time"

// TokenIssued event
type TokenIssued struct {
	TokenType    string
	AccessToken  string
	RefreshToken string
	ClientID     string
	UserID       string
	Scopes       []string
	ExpiresIn    int
	Time         time.Time
}

func (e TokenIssued) Name() string {
	return "TokenIssued"
}

func (e TokenIssued) OccurredAt() time.Time {
	if e.Time.IsZero() {
		return time.Now()
	}
	return e.Time
}
