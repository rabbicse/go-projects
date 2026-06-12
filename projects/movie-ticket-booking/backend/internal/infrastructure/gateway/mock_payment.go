package gateway

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/payment"
)

// MockPaymentGateway simulates a payment processor.
// Cards ending in "0000" are always declined; all others succeed.
type MockPaymentGateway struct{}

func NewMockPaymentGateway() *MockPaymentGateway {
	return &MockPaymentGateway{}
}

func (g *MockPaymentGateway) Charge(_ int64, _ string, card payment.CardDetails) (string, error) {
	normalized := strings.ReplaceAll(card.Number, " ", "")
	if strings.HasSuffix(normalized, "0000") {
		return "", fmt.Errorf("card declined: insufficient funds")
	}
	return "txn_" + uuid.New().String()[:8], nil
}
