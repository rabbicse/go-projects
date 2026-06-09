package shared

import "fmt"

// Money is an immutable value object representing a monetary amount in cents.
type Money struct {
	cents    int64
	currency string
}

func NewMoney(cents int64, currency string) Money {
	return Money{cents: cents, currency: currency}
}

func USD(cents int64) Money {
	return Money{cents: cents, currency: "USD"}
}

func (m Money) Cents() int64    { return m.cents }
func (m Money) Currency() string { return m.currency }

func (m Money) Add(other Money) (Money, error) {
	if m.currency != other.currency {
		return Money{}, fmt.Errorf("cannot add %s and %s", m.currency, other.currency)
	}
	return Money{cents: m.cents + other.cents, currency: m.currency}, nil
}

func (m Money) Multiply(n int) Money {
	return Money{cents: m.cents * int64(n), currency: m.currency}
}

func (m Money) String() string {
	return fmt.Sprintf("%s %.2f", m.currency, float64(m.cents)/100)
}
