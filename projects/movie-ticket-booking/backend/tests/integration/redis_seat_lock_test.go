package integration_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	redismodule "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	redisinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/redis"
)

func startRedis(t *testing.T) *goredis.Client {
	t.Helper()
	ctx := context.Background()
	container, err := redismodule.Run(ctx, "redis:7-alpine")
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	addr, err := container.Endpoint(ctx, "")
	require.NoError(t, err)

	rdb := goredis.NewClient(&goredis.Options{Addr: addr})
	require.NoError(t, rdb.Ping(ctx).Err())
	return rdb
}

func TestSeatLock_HoldAndConfirm(t *testing.T) {
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	req := booking.HoldRequest{
		SessionID:  uuid.New().String(),
		UserID:     "user-1",
		ShowtimeID: "show-1",
		MovieID:    "movie-1",
		SeatIDs:    []string{"A1", "A2"},
		HoldTTL:    60,
	}

	session, err := repo.HoldSeats(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, booking.StatusHeld, session.Status)
	assert.Equal(t, req.SeatIDs, session.SeatIDs)

	require.NoError(t, repo.ConfirmSession(ctx, req.SessionID))

	got, err := repo.GetSession(ctx, req.SessionID)
	require.NoError(t, err)
	assert.Equal(t, booking.StatusConfirmed, got.Status)
}

func TestSeatLock_DuplicateHoldFails(t *testing.T) {
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	req := booking.HoldRequest{
		SessionID:  uuid.New().String(),
		UserID:     "user-1",
		ShowtimeID: "show-dup-" + uuid.New().String()[:6],
		SeatIDs:    []string{"B1"},
		HoldTTL:    60,
	}
	_, err := repo.HoldSeats(ctx, req)
	require.NoError(t, err)

	req2 := req
	req2.SessionID = uuid.New().String()
	req2.UserID = "user-2"
	_, err = repo.HoldSeats(ctx, req2)
	assert.ErrorIs(t, err, booking.ErrSeatAlreadyHeld)
}

func TestSeatLock_Release(t *testing.T) {
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	showtimeID := "show-rel-" + uuid.New().String()[:6]
	req := booking.HoldRequest{
		SessionID:  uuid.New().String(),
		UserID:     "user-1",
		ShowtimeID: showtimeID,
		SeatIDs:    []string{"C1", "C2"},
		HoldTTL:    60,
	}
	_, err := repo.HoldSeats(ctx, req)
	require.NoError(t, err)
	require.NoError(t, repo.ReleaseSession(ctx, req.SessionID))

	// After release, same seats should be available
	req2 := req
	req2.SessionID = uuid.New().String()
	req2.UserID = "user-2"
	_, err = repo.HoldSeats(ctx, req2)
	require.NoError(t, err)
}

func TestSeatLock_HeldByMe(t *testing.T) {
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	showtimeID := "show-hbm-" + uuid.New().String()[:6]
	req := booking.HoldRequest{
		SessionID:  uuid.New().String(),
		UserID:     "user-alpha",
		ShowtimeID: showtimeID,
		SeatIDs:    []string{"D1", "D2"},
		HoldTTL:    60,
	}
	_, err := repo.HoldSeats(ctx, req)
	require.NoError(t, err)

	time.Sleep(20 * time.Millisecond)

	statusesOwner, err := repo.GetSeatStatuses(ctx, showtimeID, "user-alpha")
	require.NoError(t, err)
	for _, s := range statusesOwner {
		assert.True(t, s.HeldByMe, "seat %s should be HeldByMe for owner", s.SeatID)
	}

	statusesOther, err := repo.GetSeatStatuses(ctx, showtimeID, "user-beta")
	require.NoError(t, err)
	for _, s := range statusesOther {
		assert.False(t, s.HeldByMe, "seat %s should NOT be HeldByMe for another user", s.SeatID)
	}
}

// TestConcurrentHold_ExactlyOneWins: 10k goroutines race for one seat.
func TestConcurrentHold_ExactlyOneWins(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrency test in short mode")
	}
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	const goroutines = 10_000

	var successes, failures atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			req := booking.HoldRequest{
				SessionID:  uuid.New().String(),
				UserID:     uuid.New().String(),
				ShowtimeID: "show-concurrent",
				MovieID:    "movie-1",
				SeatIDs:    []string{"D1"},
				HoldTTL:    30,
			}
			if _, err := repo.HoldSeats(ctx, req); err == nil {
				successes.Add(1)
			} else {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), successes.Load(), "exactly one goroutine should win the seat")
	assert.Equal(t, int64(goroutines-1), failures.Load())
}

func TestSeatLock_GetSeatStatuses(t *testing.T) {
	rdb := startRedis(t)
	repo := redisinfra.NewSeatLockRepository(rdb)
	ctx := context.Background()

	showtimeID := "show-status-" + uuid.New().String()[:6]
	req := booking.HoldRequest{
		SessionID:  uuid.New().String(),
		UserID:     "u1",
		ShowtimeID: showtimeID,
		SeatIDs:    []string{"E1", "E2"},
		HoldTTL:    30,
	}
	_, err := repo.HoldSeats(ctx, req)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	statuses, err := repo.GetSeatStatuses(ctx, showtimeID, "u1")
	require.NoError(t, err)
	assert.Len(t, statuses, 2)
	for _, s := range statuses {
		assert.Equal(t, string(booking.StatusHeld), s.Status)
		assert.NotNil(t, s.ExpiresAt)
		assert.True(t, s.HeldByMe)
	}
}
