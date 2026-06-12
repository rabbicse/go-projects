package payment

import (
	"errors"
	"time"
)

type PaymentStatus string

const (
	StatusPending   PaymentStatus = "pending"
	StatusCompleted PaymentStatus = "completed"
	StatusFailed    PaymentStatus = "failed"
)

var ErrPaymentDeclined = errors.New("payment declined")

type Payment struct {
	ID          string
	SessionID   string
	UserID      string
	AmountCents int64
	Currency    string
	Status      PaymentStatus
	FailReason  string
	CreatedAt   time.Time
}

type CardDetails struct {
	Number string
	Expiry string
	CVV    string
}
