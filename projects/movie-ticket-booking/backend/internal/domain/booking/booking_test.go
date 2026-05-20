package booking_test

import (
	"testing"
	"time"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	"github.com/rabbicse/movie-ticket-booking/internal/domain/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSeat(t *testing.T) {
	tests := []struct {
		id      string
		wantErr bool
		row     string
		num     int
	}{
		{"A1", false, "A", 1},
		{"B10", false, "B", 10},
		{"a3", false, "A", 3}, // lowercase normalised
		{"1A", true, "", 0},
		{"", true, "", 0},
		{"A0", true, "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			s, err := booking.NewSeat(tc.id)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.row, s.Row)
				assert.Equal(t, tc.num, s.Number)
			}
		})
	}
}

func makeBooking(t *testing.T, status booking.Status) booking.Booking {
	t.Helper()
	seats := []booking.Seat{{ID: "A1", Row: "A", Number: 1}}
	b, err := booking.New("session-1", "user-1", "show-1", "movie-1", seats, shared.USD(1200), 10*time.Minute)
	require.NoError(t, err)
	b.Status = status
	return b
}

func TestBooking_Confirm_HappyPath(t *testing.T) {
	b := makeBooking(t, booking.StatusHeld)
	err := b.Confirm()
	require.NoError(t, err)
	assert.Equal(t, booking.StatusConfirmed, b.Status)
	assert.NotNil(t, b.ConfirmedAt)
}

func TestBooking_Confirm_AlreadyConfirmed(t *testing.T) {
	b := makeBooking(t, booking.StatusConfirmed)
	err := b.Confirm()
	assert.ErrorIs(t, err, booking.ErrInvalidStatusTransition)
}

func TestBooking_Confirm_Expired(t *testing.T) {
	b := makeBooking(t, booking.StatusHeld)
	b.ExpiresAt = time.Now().Add(-1 * time.Second) // already expired
	err := b.Confirm()
	assert.ErrorIs(t, err, booking.ErrSessionExpired)
}

func TestBooking_Release(t *testing.T) {
	b := makeBooking(t, booking.StatusHeld)
	err := b.Release()
	require.NoError(t, err)
	assert.Equal(t, booking.StatusReleased, b.Status)
}

func TestBooking_Release_NotHeld(t *testing.T) {
	b := makeBooking(t, booking.StatusConfirmed)
	err := b.Release()
	assert.ErrorIs(t, err, booking.ErrInvalidStatusTransition)
}

func TestBooking_SeatIDs(t *testing.T) {
	seats := []booking.Seat{
		{ID: "A1"}, {ID: "A2"}, {ID: "B3"},
	}
	b := booking.Booking{Seats: seats}
	assert.Equal(t, []string{"A1", "A2", "B3"}, b.SeatIDs())
}

func TestNew_NoSeats(t *testing.T) {
	_, err := booking.New("s", "u", "st", "m", nil, shared.USD(1000), time.Minute)
	assert.ErrorIs(t, err, booking.ErrNoSeatsSelected)
}

func TestNew_TotalPrice(t *testing.T) {
	seats := []booking.Seat{{ID: "A1"}, {ID: "A2"}, {ID: "A3"}}
	b, err := booking.New("s", "u", "st", "m", seats, shared.USD(1500), time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(4500), b.TotalPrice.Cents())
}
