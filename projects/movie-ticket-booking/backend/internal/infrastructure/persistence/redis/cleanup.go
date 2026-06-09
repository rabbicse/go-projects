package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// CleanConfirmedSeats removes confirmed seat keys for a finished screening.
//
// RC-03 guard: if screeningEndTime is in the future the function returns
// immediately without touching any keys. This prevents the cleanup job
// from deleting active-screening seats due to clock skew or a mis-fired cron.
func (r *SeatLockRepository) CleanConfirmedSeats(ctx context.Context, showtimeID string, screeningEndTime time.Time) (int64, error) {
	if time.Now().UTC().Before(screeningEndTime.UTC()) {
		return 0, nil
	}

	// Step 1: collect all seat keys for this showtime
	pattern := fmt.Sprintf(seatKeyFmt, showtimeID, "*")
	var seatKeys []string
	iter := r.rdb.Scan(ctx, 0, pattern, 200).Iterator()
	for iter.Next(ctx) {
		seatKeys = append(seatKeys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return 0, fmt.Errorf("scan seat keys for cleanup: %w", err)
	}
	if len(seatKeys) == 0 {
		return 0, nil
	}

	// Step 2: pipeline TTL for all keys — only delete confirmed ones (TTL == -1)
	pipe := r.rdb.Pipeline()
	ttlCmds := make([]*redis.DurationCmd, len(seatKeys))
	for i, key := range seatKeys {
		ttlCmds[i] = pipe.TTL(ctx, key)
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return 0, fmt.Errorf("pipeline ttl for cleanup: %w", err)
	}

	// Step 3: collect keys whose TTL == -1 (confirmed, no expiry)
	var toDelete []string
	for i, key := range seatKeys {
		ttl, _ := ttlCmds[i].Result()
		if ttl == -time.Second {
			toDelete = append(toDelete, key)
		}
	}
	if len(toDelete) == 0 {
		return 0, nil
	}

	// Step 4: bulk delete
	n, err := r.rdb.Del(ctx, toDelete...).Result()
	if err != nil {
		return 0, fmt.Errorf("delete confirmed seat keys: %w", err)
	}
	return n, nil
}
