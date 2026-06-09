# Concurrency Analysis

_Based on full source read — 2026-06-08_

## Summary

The application delegates all concurrency control to **Redis via Lua scripting**. There are no goroutines, mutexes, channels, or atomic operations in the application code itself. The Go server is stateless with respect to booking state — all shared mutable state lives in Redis (seats) and MongoDB (history).

This is the correct approach for a distributed system. The tradeoffs are documented below.

---

## Redis Lua Script Analysis

### `luaHoldSeats` — The Core Guarantee

```lua
local locked = {}
for i = 1, #KEYS do
    local ok = redis.call('SET', KEYS[i], ARGV[1], 'NX', 'EX', tonumber(ARGV[2]))
    if ok then
        table.insert(locked, KEYS[i])
    else
        for _, k in ipairs(locked) do redis.call('DEL', k) end
        return redis.error_reply('SEAT_TAKEN:' .. KEYS[i])
    end
end
redis.call('SET', ARGV[4], ARGV[3], 'EX', tonumber(ARGV[2]))
return 'OK'
```

**Correctness**: ✅
- Redis executes Lua scripts atomically — no other commands run between iterations.
- `SET NX EX` sets only if not exists with TTL — idempotent and race-free.
- On failure, previously locked keys are deleted in the same script — true all-or-nothing.
- Session key is written last, only if all seats succeed.

**Edge case — script timeout**: Redis has a default `lua-time-limit` of 5 seconds. For N=4 seats this is irrelevant. At scale (100-seat booking), still well within limits.

**Edge case — Redis restart mid-script**: Lua atomicity is per-command-dispatch, not persistent. If Redis crashes between the last `SET NX` and the session `SET`, some seat keys exist without a session. On TTL expiry they self-clean. The session will not be found, so the booking will be treated as expired. Acceptable.

### `luaConfirm` — Making Holds Permanent

```lua
redis.call('SET', KEYS[1], ARGV[1])   -- update session JSON to "confirmed"
redis.call('PERSIST', KEYS[1])         -- remove TTL from session
for i = 2, #KEYS do redis.call('PERSIST', KEYS[i]) end  -- remove TTL from each seat
return 'OK'
```

**Correctness**: ✅ PERSIST removes the TTL, making the keys permanent (until explicit DEL).

**Issue**: Confirmed seats never expire from Redis unless explicitly deleted. Over time the Redis keyspace grows indefinitely. There is no cleanup mechanism for confirmed seat keys. In production this is a memory leak.

### `luaRelease` — Cleanup

```lua
for _, k in ipairs(KEYS) do redis.call('DEL', k) end
return 'OK'
```

**Correctness**: ✅ Simple, correct. Deletes session + all seat keys atomically.

---

## Concurrency Test Assessment

### `TestConcurrentHold_ExactlyOneWins`

```go
const goroutines = 10_000
var successes, failures atomic.Int64
var wg sync.WaitGroup
wg.Add(goroutines)
for range goroutines {
    go func() {
        defer wg.Done()
        // ... HoldSeats for seat "D1"
    }()
}
wg.Wait()
assert.Equal(t, int64(1), successes.Load())
```

**Quality**: ✅ This is a genuine concurrency correctness test, not just a smoke test.
- 10 000 goroutines is aggressive — finds real race conditions.
- `atomic.Int64` for counters avoids a false test race.
- Uses real Redis via testcontainers — not mocked.
- The test proves the Lua NX guarantee holds under maximum contention.

**Missing tests**:
- Confirm + concurrent release race (session found in Redis but deleted before MongoDB read)
- Partial hold rollback correctness (N-1 seats succeed, Nth fails)
- GetSeatStatuses accuracy during concurrent holds

---

## Race Conditions in Application Code

### 1. Confirm vs. TTL Expiry — **Low risk**

Timeline:
1. `GetSession()` returns session (TTL > 0) ✅
2. `booking.Confirm()` checks `ExpiresAt` — passes ✅
3. Redis key expires between step 2 and `ConfirmSession()` call
4. `luaConfirm` calls `PERSIST` on an expired key — PERSIST on a non-existent key is a no-op
5. `ConfirmSession()` returns `nil` (Lua script returns "OK" regardless)
6. Booking is marked confirmed in MongoDB, but Redis seat key is gone

**Result**: Double-booking risk? No — the seat key is gone, so a subsequent `HoldSeats` for that seat will succeed (it sees no key). This means a seat could be re-sold after the original holder's TTL expired but before they clicked confirm. The application-level check `b.Confirm()` → `ErrSessionExpired` catches this if the Go-side `ExpiresAt` check fires first. However, if the Redis TTL fires in the narrow window between the `ExpiresAt` check and the `ConfirmSession` call, the session state in MongoDB will say "confirmed" but the Redis seat lock is gone.

**Mitigation needed**: `ConfirmSession` should verify the session still exists before PERSISTing.

### 2. MongoDB Save Failure on Hold — **Medium risk**

In `BookingService.HoldSeats`:
```go
if saveErr := s.bookingRepo.Save(ctx, b); saveErr != nil {
    slog.Warn("failed to persist held booking", ...)
}
return session, nil  // success returned regardless
```

If MongoDB is unavailable:
- Redis hold succeeds
- MongoDB record not created
- Client gets a valid session_id
- On confirm: `FindBySessionID` returns `ErrBookingNotFound` → confirm fails with 500
- User holds seats they can never confirm

**Mitigation needed**: Either fail the hold if MongoDB is unavailable, or implement a compensating transaction (release Redis on MongoDB failure).

### 3. Confirm Partial Failure — **Medium risk**

```go
if err := s.seatLock.ConfirmSession(ctx, sessionID); err != nil {
    return booking.Booking{}, fmt.Errorf("confirm redis session: %w", err)
}
if err := s.bookingRepo.Update(ctx, b); err != nil {
    slog.Warn("failed to update booking status in mongodb", ...)
}
```

If Redis confirm succeeds but MongoDB update fails:
- Redis: seats are permanent (no TTL), status = "confirmed"
- MongoDB: booking record still shows "held"

**Result**: Booking is effectively confirmed (seats are locked permanently), but the record says "held". A second confirm attempt would reload the "held" booking, re-confirm it in domain, re-call `ConfirmSession` (PERSIST on already-persistent keys is fine), and succeed. Idempotent — acceptable.

### 4. `GetSeatStatuses` N+1 under High Load — **Performance concern**

```go
for iter.Next(ctx) {
    sessionID, _ := r.rdb.Get(ctx, seatKey).Result()
    ttl, _ := r.rdb.TTL(ctx, seatKey).Result()
    if requestingUserID != "" {
        if session, sErr := r.GetSession(ctx, sessionID); sErr == nil {
            status.HeldByMe = session.UserID == requestingUserID
        }
    }
}
```

For a 120-seat hall with all seats held: SCAN returns 120 keys, each triggers 3 Redis commands (GET key, TTL key, GET session). That's 360+ Redis round trips per `GetSeatMap` request. With 100 concurrent users polling every 2 seconds, this is 36 000 Redis ops/second just for the seat map.

**Mitigation**: Use Redis `HGETALL` on a hash per showtime, or pipeline the commands, or use `MGET` for batch retrieval.

---

## Locking Strategy Assessment

| Strategy | Used? | Notes |
|---|---|---|
| Optimistic locking (CAS) | No | Not applicable — Redis NX is stronger |
| Pessimistic locking (mutex) | No | Replaced by Redis NX |
| Distributed lock (Redlock) | No | Single-node Redis NX is sufficient for this use case |
| Redis Lua atomic | **Yes** | Core mechanism — correct |
| MongoDB transactions | No | Not needed; MongoDB is append-only for bookings |
| Go `sync.Mutex` | No | Correct — no in-process shared state |

## Verdict

The concurrency model is **correct** for a single Redis node. The Lua approach is simpler and more correct than Redlock for this use case (single-seat or multi-seat atomic lock). The integration test is thorough.

Primary concerns are not correctness but **resilience**: MongoDB failure during hold, and the slow `GetSeatStatuses` N+1 pattern under load.
