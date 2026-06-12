# Concurrency Deep Dive

*Applies: golang-pro skill — concurrency patterns, Lua atomicity, race condition analysis*

---

## Overview

The booking system's concurrency guarantee can be stated in one sentence:  
**At most one user can hold any given seat at any given time, even under 10,000 concurrent requests.**

This is enforced entirely inside a single Redis Lua script executed atomically on the Redis server. No Go-level mutexes, no optimistic retry loops, no distributed locking protocols beyond what Redis provides natively.

---

## Key Schema

```
seat:{showtimeID}:{seatID}   →  sessionID        TTL=HoldTTL  (held)
                              →  sessionID        no TTL       (confirmed, PERSIST called)
session:{sessionID}          →  JSON(Session)    TTL=HoldTTL  (held)
                              →  JSON(Session)    no TTL       (confirmed)
```

The TTL presence/absence is the canonical source of truth for booking status:

| TTL result | Meaning |
|---|---|
| `> 0` | Held — still within checkout window |
| `-1` (PERSIST) | Confirmed — permanent booking |
| `-2` (key gone) | Released or expired |

---

## Lua Script Analysis

### `luaHoldSeats` — the critical path

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

**Atomicity guarantee:** Redis executes Lua scripts in a single-threaded, non-preemptible context. No other command can interleave between any two `redis.call` invocations inside the script. This means the entire "check all seats + lock all seats + rollback on conflict" loop is an indivisible unit.

**Why `SET … NX EX` instead of `EXISTS` + `SET`?** The classic TOCTOU race:

```
goroutine A: EXISTS seat:s1 → not found
goroutine B: EXISTS seat:s1 → not found  (interleave between A's check and set)
goroutine A: SET seat:s1 A_sessionID
goroutine B: SET seat:s1 B_sessionID   ← double-booking
```

`SET key value NX EX ttl` fuses the existence check and the write into one atomic Redis operation. The `NX` flag (Not eXists) makes it a no-op if the key already exists and returns `nil` instead of `OK`, which the Lua script uses to detect conflict.

**Rollback on partial hold:** If 3 of 4 requested seats lock successfully but seat 4 is already taken, all 3 previously locked seats are immediately `DEL`-ed within the same Lua execution. No orphaned partial holds can escape.

**Session key written inside the script:** The session JSON is written as the final step inside the Lua script (after all seats lock), guaranteeing that `session:{sessionID}` only exists if all seats are held. A `GetSession` call can never observe a session whose seats aren't all held.

---

### `luaConfirm` — RC-02 prevention

```lua
if redis.call('EXISTS', KEYS[1]) == 0 then
    return redis.error_reply('SESSION_EXPIRED')
end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('PERSIST', KEYS[1])
for i = 2, #KEYS do redis.call('PERSIST', KEYS[i]) end
return 'OK'
```

**Race condition RC-02** (time-of-check vs. time-of-confirm):

```
Timeline
────────
T0    User holds seats A1, A2  (TTL=600s)
T1    User navigates to checkout page
T2    HOLD_TTL fires — Redis deletes seat:A1, seat:A2, session:S1
T3    User clicks "Pay Now"
T4    ConfirmSession is called
T5    WITHOUT the EXISTS guard: PERSIST on a non-existent key silently succeeds,
      no booking is confirmed, but the user sees HTTP 200
```

The `EXISTS` guard at the top of `luaConfirm` detects that the session key is gone and returns `SESSION_EXPIRED`, which maps to `booking.ErrSessionExpired` → HTTP 410. The frontend can then redirect the user to re-select seats.

**`PERSIST` semantics:** Removes the TTL from a key, making it permanent. Used instead of re-`SET`-ing the key so the confirmed seat stays occupied until a deliberate admin delete or future cleanup job.

---

### `luaRelease` — RC-01 prevention

```lua
local ttl = redis.call('TTL', KEYS[1])
if ttl == -1 then
    return 'ALREADY_CONFIRMED'
end
if ttl == -2 then
    return 'NOT_FOUND'
end
for _, k in ipairs(KEYS) do redis.call('DEL', k) end
return 'OK'
```

**Race condition RC-01** (confirm + release race):

```
Timeline
────────
T0    User A confirms payment → ConfirmSession in flight
T1    User A's browser tab closes → ReleaseSession triggered by beforeunload beacon
T2    luaRelease checks TTL for session:S1
      If confirm completed first: TTL=-1 (PERSIST was called) → return 'ALREADY_CONFIRMED'
      ConfirmSession's seat keys are NOT deleted
T3    Without TTL guard: DEL would destroy confirmed seats,
      making them available for re-booking → phantom booking
```

The TTL check at position [1] (session key only) is sufficient: if `PERSIST` has been called on the session key, `TTL` returns `-1`, and the release aborts without touching any seat keys.

---

## Compensating Transaction in the Application Layer

The Lua scripts protect Redis atomicity. One layer up, the application service adds a compensating transaction for the MongoDB write:

```go
// application/booking/service.go — HoldSeats
session, err := s.seatLock.HoldSeats(ctx, req)
if err != nil {
    return booking.Session{}, err
}

if err := s.bookingRepo.Save(ctx, booking); err != nil {
    // Redis hold succeeded but MongoDB write failed.
    // Compensate: release the Redis lock so seats become available again.
    _ = s.seatLock.ReleaseSession(ctx, req.SessionID)
    return booking.Session{}, fmt.Errorf("persist booking: %w", err)
}
```

Without this rollback, a MongoDB write failure would leave seats permanently held in Redis with no booking record in the DB — invisible to the user, impossible to confirm, expiring only after HOLD_TTL.

The `TestHoldSeats_CompensatingTransaction` integration test verifies this path: MongoDB `Save` returns an error, and the test asserts that `ReleaseSession` was called exactly once.

---

## Pipeline Optimization — `GetSeatStatuses`

The seat map endpoint (`GET /showtimes/:id/seats`) is called every 2 seconds by the frontend. The original naïve implementation would require 2 Redis round trips per seat (GET + TTL). For an 80-seat hall that's 160 serial round trips.

The optimized implementation uses two pipelined batches:

```
Round trip 1: SCAN seat:{showtimeID}:*  → collect all seat keys
Round trip 2: Pipeline (GET key + TTL key) × N  → 1 round trip regardless of seat count
Round trip 3: Pipeline GET session:{id} × M  → 1 round trip for HeldByMe resolution
              where M = unique held sessions (≤ N)
```

**Complexity:**
- Before: O(N) round trips
- After: O(1) round trips (3 always, regardless of hall size)

For 80 seats with 10 distinct holders: 3 round trips vs. 160. Under the 2-second polling interval this saves ~80ms of Redis latency per user per refresh.

---

## Concurrency Test Results

`TestConcurrentHold_ExactlyOneWins` sends 10,000 goroutines simultaneously to hold seat `D1`:

```
goroutines:    10,000
successes:     1        (exactly one winner)
failures:      9,999    (ErrSeatAlreadyHeld — correct)
race detector: PASS     (go test -race)
```

This test proves the Lua NX invariant holds under worst-case Go goroutine concurrency. The Redis single-threaded execution model means contention manifests as serialized NX attempts, not data corruption.

---

## Redis Key Lifecycle Diagram

```
Hold requested
      │
      ▼
luaHoldSeats (all NX succeed)
      │
      ├─ seat:{show}:{id} ← sessionID  [TTL=600s]  ──┐
      │                                               │ HOLD_TTL fires
      └─ session:{id}     ← JSON       [TTL=600s]  ──┘
                                                       ▼
                                                 Keys auto-deleted
                                                 (seats become available)

Confirm payment
      │
      ▼
luaConfirm (EXISTS guard)
      │
      ├─ seat:{show}:{id} ← sessionID  [PERSIST — no TTL]
      └─ session:{id}     ← JSON       [PERSIST — no TTL]
                                        ▲
                                        │ permanent until admin cleanup

Release (cancel)
      │
      ▼
luaRelease (TTL guard)
      │
      ├─ if TTL=-1: ALREADY_CONFIRMED → abort (RC-01 prevention)
      ├─ if TTL=-2: NOT_FOUND → no-op (already expired)
      └─ else: DEL all keys → seats become available
```

---

## Threat Model Summary

| Race | Trigger | Protection | Layer |
|---|---|---|---|
| Double-booking (same seat two buyers) | Concurrent hold requests | `SET NX` inside Lua | Redis |
| Partial hold leak | N seats requested, K succeed, N-K fail | Rollback loop inside Lua | Redis |
| Phantom confirm (hold expired before pay) | Slow user + short HOLD_TTL | `EXISTS` guard in `luaConfirm` | Redis |
| Confirmed seat released by stale beacon | Browser unload after confirm | TTL guard in `luaRelease` | Redis |
| Redis hold + MongoDB mismatch | MongoDB transient error | Compensating `ReleaseSession` | Go application |
| Stale seat map during rapid selection | Frontend debounce + poll overlap | Optimistic `selectedSeats` override | Frontend |
