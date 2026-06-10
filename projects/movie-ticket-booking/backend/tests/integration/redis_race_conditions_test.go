package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	redisinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/redis"
)

// TestRC01_ReleaseAfterConfirmIsBlocked covers the confirm+release race:
// once a session is confirmed (TTL removed via PERSIST), a subsequent release
// must return ErrInvalidStatusTransition and leave the seats in confirmed state.
func TestRC01_ReleaseAfterConfirmIsBlocked(t *testing.T) {
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	showtimeID := "show-rc01-" + uuid.New().String()[:6]
	sessionID := uuid.New().String()

	_, err := repo.HoldSeats(ctx, booking.HoldRequest{
		SessionID:  sessionID,
		UserID:     "user-1",
		ShowtimeID: showtimeID,
		MovieID:    "movie-1",
		SeatIDs:    []string{"A1", "A2"},
		HoldTTL:    60,
	})
	require.NoError(t, err)
	require.NoError(t, repo.ConfirmSession(ctx, sessionID))

	// Release arriving after confirm must be rejected.
	err = repo.ReleaseSession(ctx, sessionID)
	assert.ErrorIs(t, err, booking.ErrInvalidStatusTransition,
		"release after confirm must return ErrInvalidStatusTransition")

	// Seats must remain in confirmed state — not freed.
	statuses, err := repo.GetSeatStatuses(ctx, showtimeID, "user-1")
	require.NoError(t, err)
	require.Len(t, statuses, 2)
	for _, s := range statuses {
		assert.Equal(t, string(booking.StatusConfirmed), s.Status,
			"seat %s must remain confirmed after blocked release", s.SeatID)
	}
}

// TestRC02_ConfirmAfterExpiredHoldFails covers the TTL boundary race:
// after the hold TTL fires, ConfirmSession must return an error (not silently succeed
// with stale state). The Lua EXISTS guard in luaConfirm and the GetSession lookup
// both contribute to this safety net.
func TestRC02_ConfirmAfterExpiredHoldFails(t *testing.T) {
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	showtimeID := "show-rc02-" + uuid.New().String()[:6]
	sessionID := uuid.New().String()

	_, err := repo.HoldSeats(ctx, booking.HoldRequest{
		SessionID:  sessionID,
		UserID:     "user-2",
		ShowtimeID: showtimeID,
		MovieID:    "movie-1",
		SeatIDs:    []string{"B1"},
		HoldTTL:    1, // intentionally short to trigger expiry
	})
	require.NoError(t, err)

	time.Sleep(1500 * time.Millisecond) // wait for Redis TTL to fire

	err = repo.ConfirmSession(ctx, sessionID)
	require.Error(t, err, "confirm after hold expiry must return an error")
	assert.True(t,
		errors.Is(err, booking.ErrSessionNotFound) || errors.Is(err, booking.ErrSessionExpired),
		"expected ErrSessionNotFound or ErrSessionExpired, got: %v", err,
	)

	// Seats are freed after TTL — new hold must succeed.
	_, err = repo.HoldSeats(ctx, booking.HoldRequest{
		SessionID:  uuid.New().String(),
		UserID:     "user-other",
		ShowtimeID: showtimeID,
		MovieID:    "movie-1",
		SeatIDs:    []string{"B1"},
		HoldTTL:    60,
	})
	assert.NoError(t, err, "seat freed by TTL must be holdable again")
}

// TestRC03_CleanupSkipsActiveScreening verifies the RC-03 guard:
// CleanConfirmedSeats is a no-op when the screening end time is in the future,
// preventing accidental cleanup due to clock skew or a mis-fired cron.
func TestRC03_CleanupSkipsActiveScreening(t *testing.T) {
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	showtimeID := "show-rc03-live-" + uuid.New().String()[:6]
	sessionID := uuid.New().String()

	_, err := repo.HoldSeats(ctx, booking.HoldRequest{
		SessionID:  sessionID,
		UserID:     "user-3",
		ShowtimeID: showtimeID,
		MovieID:    "movie-1",
		SeatIDs:    []string{"C1", "C2"},
		HoldTTL:    300,
	})
	require.NoError(t, err)
	require.NoError(t, repo.ConfirmSession(ctx, sessionID))

	// Screening still in progress — cleanup must leave seats untouched.
	n, err := repo.CleanConfirmedSeats(ctx, showtimeID, time.Now().Add(2*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(0), n, "cleanup must not delete seats while screening is active")

	statuses, err := repo.GetSeatStatuses(ctx, showtimeID, "")
	require.NoError(t, err)
	assert.Len(t, statuses, 2, "confirmed seats must survive the no-op cleanup")
}

// TestRC03_CleanupConfirmedSeatsAfterScreening verifies that confirmed seat keys
// are removed once the screening has ended, freeing Redis memory.
func TestRC03_CleanupConfirmedSeatsAfterScreening(t *testing.T) {
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	showtimeID := "show-rc03-done-" + uuid.New().String()[:6]
	sessionID := uuid.New().String()

	_, err := repo.HoldSeats(ctx, booking.HoldRequest{
		SessionID:  sessionID,
		UserID:     "user-4",
		ShowtimeID: showtimeID,
		MovieID:    "movie-1",
		SeatIDs:    []string{"D1", "D2", "D3"},
		HoldTTL:    300,
	})
	require.NoError(t, err)
	require.NoError(t, repo.ConfirmSession(ctx, sessionID))

	// Screening ended 1 minute ago — cleanup must remove the 3 confirmed seat keys.
	screeningEnd := time.Now().Add(-time.Minute)
	n, err := repo.CleanConfirmedSeats(ctx, showtimeID, screeningEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n, "cleanup must remove exactly the 3 confirmed seat keys")

	statuses, err := repo.GetSeatStatuses(ctx, showtimeID, "")
	require.NoError(t, err)
	assert.Empty(t, statuses, "no seat keys must remain after cleanup")
}

// TestRC03_CleanupOnlyConfirmedSeats verifies the cleanup boundary:
// held seats (with TTL) must not be deleted by CleanConfirmedSeats.
func TestRC03_CleanupOnlyConfirmedSeats(t *testing.T) {
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	showtimeID := "show-rc03-mix-" + uuid.New().String()[:6]

	// Confirm 2 seats.
	sessionConfirmed := uuid.New().String()
	_, err := repo.HoldSeats(ctx, booking.HoldRequest{
		SessionID:  sessionConfirmed,
		UserID:     "user-5",
		ShowtimeID: showtimeID,
		MovieID:    "movie-1",
		SeatIDs:    []string{"E1", "E2"},
		HoldTTL:    300,
	})
	require.NoError(t, err)
	require.NoError(t, repo.ConfirmSession(ctx, sessionConfirmed))

	// Hold 2 more seats (not confirmed — still have TTL).
	_, err = repo.HoldSeats(ctx, booking.HoldRequest{
		SessionID:  uuid.New().String(),
		UserID:     "user-6",
		ShowtimeID: showtimeID,
		MovieID:    "movie-1",
		SeatIDs:    []string{"E3", "E4"},
		HoldTTL:    300,
	})
	require.NoError(t, err)

	// Screening ended — cleanup runs.
	n, err := repo.CleanConfirmedSeats(ctx, showtimeID, time.Now().Add(-time.Minute))
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "cleanup must only remove the 2 confirmed seats, not the 2 held ones")

	// Held seats must still be present.
	statuses, err := repo.GetSeatStatuses(ctx, showtimeID, "")
	require.NoError(t, err)
	assert.Len(t, statuses, 2, "held seats must survive cleanup")
	for _, s := range statuses {
		assert.Equal(t, string(booking.StatusHeld), s.Status)
	}
}
