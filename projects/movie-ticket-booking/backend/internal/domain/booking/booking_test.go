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

func TestNew_SelfAssignsID(t *testing.T) {
	seats := []booking.Seat{{ID: "A1"}}
	b, err := booking.New("s", "u", "st", "m", seats, shared.USD(1000), time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, b.ID, "New() must assign a non-empty ID")
}

func TestNew_UniqueIDs(t *testing.T) {
	seats := []booking.Seat{{ID: "A1"}}
	b1, _ := booking.New("s1", "u", "st", "m", seats, shared.USD(1000), time.Minute)
	b2, _ := booking.New("s2", "u", "st", "m", seats, shared.USD(1000), time.Minute)
	assert.NotEqual(t, b1.ID, b2.ID, "each booking must have a unique ID")
}

func TestBooking_Expire(t *testing.T) {
	b := makeBooking(t, booking.StatusHeld)
	require.NoError(t, b.Expire())
	assert.Equal(t, booking.StatusExpired, b.Status)
}

func TestBooking_Expire_NotHeld(t *testing.T) {
	b := makeBooking(t, booking.StatusConfirmed)
	assert.ErrorIs(t, b.Expire(), booking.ErrInvalidStatusTransition)
}

func TestBooking_PopEvents_New(t *testing.T) {
	seats := []booking.Seat{{ID: "A1"}}
	b, err := booking.New("session-1", "user-1", "show-1", "movie-1", seats, shared.USD(1500), 10*time.Minute)
	require.NoError(t, err)

	evts := b.PopEvents()
	require.Len(t, evts, 1, "New() must emit one BookingCreated event")
	assert.Equal(t, booking.EventNameBookingCreated, evts[0].EventName())
}

func TestBooking_PopEvents_ClearsAfterPop(t *testing.T) {
	seats := []booking.Seat{{ID: "A1"}}
	b, _ := booking.New("s", "u", "st", "m", seats, shared.USD(1000), time.Minute)
	b.PopEvents() // drain creation event

	evts := b.PopEvents()
	assert.Empty(t, evts, "PopEvents() must clear events after first call")
}

func TestBooking_PopEvents_Confirm(t *testing.T) {
	seats := []booking.Seat{{ID: "A1"}}
	b, _ := booking.New("s", "u", "st", "m", seats, shared.USD(1000), time.Minute)
	b.PopEvents() // drain creation event

	require.NoError(t, b.Confirm())
	evts := b.PopEvents()
	require.Len(t, evts, 1)
	assert.Equal(t, booking.EventNameBookingConfirmed, evts[0].EventName())
}

func TestBooking_PopEvents_Release(t *testing.T) {
	seats := []booking.Seat{{ID: "A1"}}
	b, _ := booking.New("s", "u", "st", "m", seats, shared.USD(1000), time.Minute)
	b.PopEvents()

	require.NoError(t, b.Release())
	evts := b.PopEvents()
	require.Len(t, evts, 1)
	assert.Equal(t, booking.EventNameBookingReleased, evts[0].EventName())
}

func TestBooking_PopEvents_Expire(t *testing.T) {
	seats := []booking.Seat{{ID: "A1"}}
	b, _ := booking.New("s", "u", "st", "m", seats, shared.USD(1000), time.Minute)
	b.PopEvents()

	require.NoError(t, b.Expire())
	evts := b.PopEvents()
	require.Len(t, evts, 1)
	assert.Equal(t, booking.EventNameBookingExpired, evts[0].EventName())
}
