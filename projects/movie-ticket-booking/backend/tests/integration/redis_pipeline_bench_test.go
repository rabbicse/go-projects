package integration_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	redismodule "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
	redisinfra "github.com/rabbicse/movie-ticket-booking/internal/infrastructure/persistence/redis"
)

func startRedisBench(b *testing.B) *goredis.Client {
	b.Helper()
	ctx := context.Background()
	container, err := redismodule.Run(ctx, "redis:7-alpine")
	if err != nil {
		b.Fatalf("start redis container: %v", err)
	}
	b.Cleanup(func() { _ = container.Terminate(ctx) })

	addr, err := container.Endpoint(ctx, "")
	if err != nil {
		b.Fatalf("redis endpoint: %v", err)
	}
	rdb := goredis.NewClient(&goredis.Options{Addr: addr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		b.Fatalf("redis ping: %v", err)
	}
	return rdb
}

// BenchmarkGetSeatStatuses measures GetSeatStatuses with N pre-held seats.
// The implementation uses 2 Redis round trips (SCAN + 2 pipelines) regardless
// of seat count. Run with: go test -bench=BenchmarkGetSeatStatuses ./tests/integration/
func BenchmarkGetSeatStatuses(b *testing.B) {
	for _, seatCount := range []int{10, 50, 100} {
		b.Run(fmt.Sprintf("%d_seats", seatCount), func(b *testing.B) {
			rdb := startRedisBench(b)
			repo := redisinfra.NewSeatLockRepository(rdb)
			ctx := context.Background()
			showtimeID := "bench-show-" + uuid.New().String()[:8]

			// Pre-hold seatCount seats in batches of 4 (max per session).
			for held := 0; held < seatCount; {
				batchSize := 4
				if held+batchSize > seatCount {
					batchSize = seatCount - held
				}
				seats := make([]string, batchSize)
				for i := range batchSize {
					seats[i] = fmt.Sprintf("R%02dS%02d", (held+i)/10, (held+i)%10)
				}
				if _, err := repo.HoldSeats(ctx, booking.HoldRequest{
					SessionID:  uuid.New().String(),
					UserID:     "bench-user",
					ShowtimeID: showtimeID,
					MovieID:    "movie-bench",
					SeatIDs:    seats,
					HoldTTL:    600,
				}); err != nil {
					b.Fatalf("setup hold: %v", err)
				}
				held += batchSize
			}

			b.ResetTimer()
			b.ReportAllocs()

			for range b.N {
				if _, err := repo.GetSeatStatuses(ctx, showtimeID, "bench-user"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
