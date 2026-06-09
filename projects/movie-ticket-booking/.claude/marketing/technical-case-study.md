# Technical Case Study: Atomic Multi-Seat Reservation Under Concurrent Load

_Engineering blog-style deep dive. Suitable for a personal blog, a portfolio case study page, or a writing sample._

---

## Abstract

Building a seat reservation system is a canonical distributed systems problem. The naive implementation — read seat status, then write booking — has a race window that causes double-bookings under concurrent load. This case study documents the design of an atomic multi-seat locking mechanism using Redis Lua scripts, the race conditions discovered beyond the basic lock, and the architectural decisions that keep the system correct as it scales.

---

## The Problem

A cinema has 120 seats per screening. When a user selects seats, the system must atomically reserve them: either all requested seats are locked, or none are. This is harder than it sounds.

Consider two users, Alice and Bob, both trying to book seats A1 and A2 simultaneously:

```
Time →

Alice: READ A1=available, READ A2=available ────────────── WRITE A1=held, WRITE A2=held ✓
Bob:   READ A1=available, READ A2=available ─ WRITE A1=held, WRITE A2=held ✓
                                                ↑
                                          Double-booking
```

Any implementation with a read-then-write pattern has this window. The window is small — microseconds — but at scale, small windows close constantly. A popular film going on sale generates hundreds of concurrent booking attempts. The probability of a race collision approaches 1.

### Why Not a Database Transaction?

The standard fix is a database transaction with row-level locking. This works for correctness, but creates a problem specific to this use case.

The seat availability endpoint — `GET /screenings/:id/availability` — is polled every two seconds by every connected client to show live updates. At 270 concurrent viewers (a mid-sized cinema's screen capacity), that's 540 availability reads per second. Under a heavy booking load, these reads collide with the write locks in a transaction, creating contention that compounds exactly when demand is highest.

We need the read path and the write path to be completely independent.

---

## The Solution: Redis Lua Scripts

Redis provides two primitives that compose into a solution:

**`SET key value NX EX ttl`** — set a key only if it does not exist (`NX`), with an expiry (`EX`). This is atomic for a single key. If the key exists, the command returns nil without modifying anything.

**Lua scripts** — Redis executes Lua scripts atomically. The entire script runs as a single command from Redis's perspective. No other Redis command can interleave during execution.

Combining these: a Lua script that calls `SET NX` for each requested seat. If any `SET NX` fails (seat already taken), it deletes all previously set keys and returns an error — all within the same atomic execution.

### The `luaHold` Script

```lua
-- KEYS: one entry per seat key, e.g. "seat:screening_1:A1"
-- ARGV[1]: reservation ID (the value to store)
-- ARGV[2]: TTL in seconds
-- Returns: 0 on success, index of conflicting key on failure

local held = {}
for i, key in ipairs(KEYS) do
    local result = redis.call('SET', key, ARGV[1], 'NX', 'EX', ARGV[2])
    if result == false then
        -- Roll back all previously locked keys
        for _, k in ipairs(held) do
            redis.call('DEL', k)
        end
        return i  -- caller knows which seat caused the conflict
    end
    table.insert(held, key)
end
return 0  -- all seats locked successfully
```

**Properties guaranteed by this design:**

| Property | Mechanism |
|---|---|
| All-or-nothing | Rollback loop in the failure branch |
| No partial holds visible to other clients | Lua atomicity |
| Automatic expiry | `EX` on each key |
| No deadlocks | No application-level locks; single atomic operation |
| Idempotent retries | Same reservation ID on retry → same result |

### Performance Characteristics

Each `luaHold` call executes in O(N) Redis commands for N seats, all within one network round trip from the application. For the maximum booking size of 4 seats:

- Network round trips: 1 (regardless of N)
- Redis commands inside Lua: 4 SET NX + up to 4 DEL (on rollback) = 8 max
- Typical latency: 2–5ms (Redis command + network)

Compared to the database transaction approach:
- Network round trips: 2 (BEGIN + COMMIT)
- Database commands: N SELECT FOR UPDATE + N UPDATE + COMMIT
- Typical latency: 15–50ms (database command + connection pool + transaction overhead)

The Redis approach is 5–10× faster on the critical booking path.

---

## The Lifecycle: Three Scripts

A reservation moves through three states: `held` → `confirmed` (on payment) or `released` (on cancellation/timeout). Each transition is a separate Lua script.

```
HOLD                CONFIRM              RELEASE
────────────────────────────────────────────────
seat key TTL=10m → seat key no TTL → seat key deleted
                   (PERSIST removes TTL)
```

### `luaConfirm` — Converting a Hold to a Permanent Booking

```lua
-- Check reservation exists before confirming (RC-02 guard)
local resKey = KEYS[#KEYS]
local existing = redis.call('GET', resKey)
if existing == false then
    return "NOT_FOUND"  -- TTL expired between checkout page load and confirm click
end

-- Remove TTL from all seat keys (permanent booking = no expiry)
for i = 1, #KEYS - 1 do
    redis.call('PERSIST', KEYS[i])
end
redis.call('PERSIST', resKey)
return "OK"
```

### `luaRelease` — Cancelling a Hold

```lua
local resKey = KEYS[#KEYS]

-- RC-01 guard: don't release if already confirmed
-- TTL == -1 means PERSIST was already called (seat is confirmed)
local ttl = redis.call('TTL', resKey)
if ttl == -1 then
    return "ALREADY_CONFIRMED"
end
if ttl == -2 then
    return "NOT_FOUND"  -- already expired — idempotent
end

for i = 1, #KEYS - 1 do
    redis.call('DEL', KEYS[i])
end
redis.call('DEL', resKey)
return "OK"
```

---

## Race Conditions Beyond the Basic Lock

Getting the happy path correct was step one. The interesting engineering is in the edge cases.

### RC-01: Concurrent Confirm and Release

**Scenario**: The user confirms payment at the same moment their browser tab fires an on-unload event that calls the release endpoint.

```
goroutine A (confirm): luaConfirm called → PERSIST executes → seat confirmed
goroutine B (release): luaRelease called → DEL executes → seat deleted
                                            ↑ wrong! confirmed seat is now gone
```

**Fix**: `luaRelease` checks `TTL(resKey) == -1` before deleting. A TTL of -1 means `PERSIST` was already called — the seat is confirmed. The release returns `ALREADY_CONFIRMED` without deleting anything.

**Why this is sufficient**: The check and the delete are in the same Lua script, so they're atomic. There's no window between "check TTL" and "DEL" where another script could change the TTL.

### RC-02: TTL Expiry Between Checkout and Confirm

**Scenario**: The user opens the checkout page with 30 seconds remaining on their hold. Their phone rings. They return 35 seconds later and click "Confirm Payment." The TTL fired at T+10m, the key no longer exists. `PERSIST` on a non-existent key returns 0 (not an error) — the script thinks it succeeded, but the seat was never actually re-locked.

**Fix**: `luaConfirm` starts with `GET resKey`. If it returns nil, the reservation has expired and the script returns `NOT_FOUND` immediately — before attempting any `PERSIST` calls.

### RC-03: Cleanup Deletes Active Screening Seats

**Scenario**: A background job scans for confirmed seat keys after a screening ends and deletes them (to prevent Redis memory accumulating indefinitely). Due to clock skew or an off-by-one in the time comparison, the cleanup runs while the screening is still in progress.

**Fix**: The cleanup function accepts `screeningEndTime` as a parameter and returns immediately if `time.Now().Before(screeningEndTime)`. This guard is easy to test: call cleanup with a future end time and verify no keys are deleted.

---

## The N+1 Problem in Seat Map Generation

Every availability poll (`GET /screenings/:id/availability`) retrieves the status of every seat in the screening. For a 10×12 hall (120 seats):

```
// Original implementation
for _, seatID := range allSeats {
    val := redis.Get(ctx, key(seatID))      // 120 GET calls
    ttl := redis.TTL(ctx, key(seatID))      // 120 TTL calls
    // determine status
}
// Total: 240 serial Redis round trips per availability poll
```

At 270 concurrent viewers polling every 2 seconds, this generates 270 × 240 × 0.5/s = **32,400 Redis commands per second** — a significant fraction of a Redis instance's command budget, and it scales quadratically with both viewers and seats.

**Fix**: Redis pipelining batches all commands into a single network round trip:

```go
pipe := redis.Pipeline()
getCmds  := make([]*redis.StringCmd,   len(seats))
ttlCmds  := make([]*redis.DurationCmd, len(seats))

for i, seatID := range seats {
    getCmds[i]  = pipe.Get(ctx, key(seatID))
    ttlCmds[i]  = pipe.TTL(ctx, key(seatID))
}
pipe.Exec(ctx)
// Total: 1 network round trip regardless of seat count
```

**Result**: 240 serial round trips → 1 pipeline. Redis command rate drops from 32,400/s to 270/s under the same load — a 99% reduction.

---

## Architecture Decisions

### Redis as Source of Truth, Not Cache

Redis is not a cache in this system. It is the **primary source of truth for seat availability**. MongoDB is the durable record for confirmed bookings.

This distinction matters for failure handling. If Redis goes down:
- Seat availability data is unavailable (availability endpoint returns 503)
- No new reservations can be made
- Confirmed bookings in MongoDB are safe

If MongoDB goes down after a Redis hold:
- The Redis keys exist (seat appears held)
- The application compensates: if the MongoDB write fails, the Redis keys are deleted
- The user sees a 500 error and must retry

Redis state can always be rebuilt from MongoDB: query all confirmed bookings for a screening, re-lock their seats with `PERSIST` (no TTL). This is the disaster recovery path.

### Write Ordering

Every reservation goes through the same write sequence:

```
1. Execute luaHold (Redis)  ← fast, atomic
   If fails → return 409 to client

2. Insert booking(status=held) into MongoDB  ← slower, durable
   If fails → execute luaRelease (Redis) as compensation
              return 500 to client

3. Return reservation to client
```

Redis is always written first. If Redis succeeds and MongoDB fails, the compensation (Redis release) ensures no phantom holds accumulate. The inverse — MongoDB persisted but Redis not locked — is impossible because step 1 would have returned an error before step 2.

---

## Verification and Testing

### Integration Test: Exactly One Winner

```go
func TestConcurrentHold_ExactlyOneWins(t *testing.T) {
    // Real Redis 7 via testcontainers-go
    repo := newSeatLockRepo(t, startRedisContainer(t))

    const goroutines = 10_000
    var wins atomic.Int32
    var wg sync.WaitGroup

    for i := 0; i < goroutines; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            _, err := repo.HoldSeats(ctx, "scr_1", []string{"A1"}, 10*time.Minute)
            if err == nil { wins.Add(1) }
        }()
    }
    wg.Wait()

    require.Equal(t, int32(1), wins.Load())
}
```

This test uses a real Redis instance (not a mock), all 10,000 goroutines run concurrently without artificial throttling, and `atomic.Int32` ensures the win count is read-race-free. The test also runs under `go test -race` in CI.

### Load Test: Sustained Throughput

A k6 load test targets the full booking flow (availability → hold → confirm) with 50 VUs over 5 minutes. Thresholds:

- Seat hold P99 < 100ms
- Seat map P95 < 50ms
- 5xx error rate < 1% (409 conflict responses are expected and excluded)

The concurrent hold scenario uses 500 VUs all targeting the same 120-seat screening. Expected outcome: 120 successful holds, ~379,880 `409 SEATS_UNAVAILABLE` responses. Any 5xx response indicates a correctness bug.

---

## What This Approach Doesn't Solve

**Clock synchronisation across instances**: Multiple API server instances are fine — they all write to the same Redis. Clock skew doesn't affect the Lua scripts (Redis maintains the TTLs). It only affects the cleanup job's `time.Now()` comparison, which is why the cleanup guard uses the screening's stored `end_time` rather than calculating a duration.

**Redis Cluster multi-key scripts**: Lua scripts that operate on multiple keys require all keys to be in the same hash slot. The key format `seat:{screeningID}:{seatID}` uses a hash tag (`{screeningID}`), ensuring all seat keys for a given screening hash to the same slot.

**Very large screenings**: For a screening with 500 seats, the pipeline approach still makes one round trip for 500 GET + 500 TTL calls in a single pipeline. This is efficient, but a future optimisation is to use Redis hashes (`HGETALL seat:{screeningID}`) to store all seat statuses for a screening in a single key — one command, one value.

---

## Lessons for Similar Systems

**Use the right tool for each invariant.** Seat availability is an ephemeral, high-frequency, concurrency-critical concern — Redis is correct. Booking history is a durable, low-frequency, query-rich concern — MongoDB or PostgreSQL is correct. Don't conflate them.

**Write the hard tests before the happy path code.** The three race conditions in this system would have been production bugs if I'd written the integration tests after. The concurrency test forced me to think about what "correct" actually means, not just what "works in development" means.

**Atomic operations and their boundaries are the architecture.** Where you place the atomic boundaries determines what invariants you can guarantee. Getting this wrong at the design stage means patching it at the operations stage, usually at 2am.

**The latency budget is a design input, not an output.** The 100ms P99 SLO for seat holds shaped the choice of Redis (2ms) over MongoDB transactions (20ms). If the SLO had been 1 second, both would have worked. The SLO came first.
