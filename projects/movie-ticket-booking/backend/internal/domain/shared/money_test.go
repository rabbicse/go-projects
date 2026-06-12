package shared_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
)

// ── Constructors ──────────────────────────────────────────────────────────────

func TestNewMoney_StoresCentsAndCurrency(t *testing.T) {
	m := shared.NewMoney(1500, "USD")
	assert.Equal(t, int64(1500), m.Cents())
	assert.Equal(t, "USD", m.Currency())
}

func TestUSD_CreatesDollarMoney(t *testing.T) {
	m := shared.USD(2000)
	assert.Equal(t, int64(2000), m.Cents())
	assert.Equal(t, "USD", m.Currency())
}

func TestNewMoney_ZeroCents(t *testing.T) {
	m := shared.NewMoney(0, "EUR")
	assert.Equal(t, int64(0), m.Cents())
}

func TestNewMoney_NegativeCents_AllowedByValueObject(t *testing.T) {
	// Money is an immutable VO — it stores whatever is given.
	// Business rules (no negative prices) live in the domain entities that use it.
	m := shared.NewMoney(-100, "USD")
	assert.Equal(t, int64(-100), m.Cents())
}

// ── Add ───────────────────────────────────────────────────────────────────────

func TestAdd_SameCurrency_ReturnsSum(t *testing.T) {
	a := shared.USD(1500)
	b := shared.USD(500)
	result, err := a.Add(b)
	require.NoError(t, err)
	assert.Equal(t, int64(2000), result.Cents())
	assert.Equal(t, "USD", result.Currency())
}

func TestAdd_DifferentCurrencies_ReturnsError(t *testing.T) {
	a := shared.USD(1000)
	b := shared.NewMoney(1000, "EUR")
	_, err := a.Add(b)
	assert.Error(t, err)
}

func TestAdd_ZeroAmount_ReturnsSameValue(t *testing.T) {
	a := shared.USD(1500)
	zero := shared.USD(0)
	result, err := a.Add(zero)
	require.NoError(t, err)
	assert.Equal(t, int64(1500), result.Cents())
}

func TestAdd_Immutability_OriginalUnchanged(t *testing.T) {
	a := shared.USD(1000)
	b := shared.USD(500)
	_, err := a.Add(b)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), a.Cents(), "Add must not mutate the receiver")
}

// ── Multiply ──────────────────────────────────────────────────────────────────

func TestMultiply_ByPositiveInt_ReturnsProduct(t *testing.T) {
	m := shared.USD(1500)
	result := m.Multiply(3)
	assert.Equal(t, int64(4500), result.Cents())
	assert.Equal(t, "USD", result.Currency())
}

func TestMultiply_ByZero_ReturnsZero(t *testing.T) {
	m := shared.USD(1500)
	result := m.Multiply(0)
	assert.Equal(t, int64(0), result.Cents())
}

func TestMultiply_ByOne_ReturnsSameValue(t *testing.T) {
	m := shared.USD(1500)
	result := m.Multiply(1)
	assert.Equal(t, int64(1500), result.Cents())
}

func TestMultiply_Immutability_OriginalUnchanged(t *testing.T) {
	m := shared.USD(1000)
	_ = m.Multiply(5)
	assert.Equal(t, int64(1000), m.Cents(), "Multiply must not mutate the receiver")
}

// ── String ────────────────────────────────────────────────────────────────────

func TestString_FormatsCorrectly(t *testing.T) {
	tests := []struct {
		cents    int64
		currency string
		want     string
	}{
		{1500, "USD", "USD 15.00"},
		{100, "USD", "USD 1.00"},
		{1, "EUR", "EUR 0.01"},
		{0, "GBP", "GBP 0.00"},
	}
	for _, tc := range tests {
		m := shared.NewMoney(tc.cents, tc.currency)
		assert.Equal(t, tc.want, m.String())
	}
}

// ── Booking price calculation ─────────────────────────────────────────────────

func TestBookingPriceCalculation_ThreeSeats(t *testing.T) {
	// Mirrors what booking.New does: pricePerSeat.Multiply(len(seats))
	pricePerSeat := shared.USD(1500)
	total := pricePerSeat.Multiply(3)
	assert.Equal(t, int64(4500), total.Cents())
}
