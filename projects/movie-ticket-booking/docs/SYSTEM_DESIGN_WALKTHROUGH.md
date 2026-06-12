# System Design Walkthrough

A detailed walkthrough of the Cinema Booking System's architecture, suitable for system design interviews and engineering reviews.

---

## Requirements

### Functional Requirements

1. Users can browse movies and showtimes
2. Users can view real-time seat availability for a showtime
3. Users can select 1–4 seats and hold them for 10 minutes
4. Users can confirm a hold (completing the booking) or release it
5. Users can view their booking history
6. Administrators can add movies and showtimes

### Non-Functional Requirements

1. **No double-booking**: A seat must never be assigned to two users simultaneously
2. **Hold expiry**: Unredeemed holds automatically expire, releasing seats
3. **Real-time seat map**: Seat state changes (held/released/confirmed) visible within 2 seconds
4. **Low latency**: Hold operations complete in < 50ms (LAN), < 100ms (WAN)

---

## High-Level Architecture

```
┌──────────────┐    HTTP     ┌──────────────────┐    Redis    ┌──────────┐
│  Browser     │ ──────────► │  Next.js 15       │ ─────────► │  Redis 7 │
│  (React)     │ ◄────────── │  (SSR + Proxy)    │            │          │
└──────────────┘             └──────────────────┘            └──────────┘
                                      │                             ▲
                                      │ /api/v1/*                   │
                                      ▼                             │
                             ┌──────────────────┐    Redis    ──────┘
                             │  Go / Gin        │ ────────────────►
                             │  HTTP Server     │                  ┌──────────┐
                             │  :8080           │    MongoDB  ────►│ MongoDB 7│
                             └──────────────────┘                  └──────────┘
```

**Key design choice**: Next.js acts as a BFF (Backend for Frontend). Browser requests go to Next.js on port 3000, which proxies `/api/v1/*` to the Go backend on port 8080. This avoids CORS issues and allows the frontend to add its own middleware layer later.

---

## The Core Problem: Atomic Seat Reservation

### Why Naive Locking Fails

A typical implementation reads, checks, then writes:

```
T1: Read seat A → available
T2: Read seat A → available
T1: Set seat A = T1's session ← succeeds
T2: Set seat A = T2's session ← overwrites T1! Double-booked.
```

This is a classic TOCTOU (Time of Check to Time of Use) race condition.

### Why Optimistic Locking Partially Solves It

Using `WATCH/MULTI/EXEC` in Redis:

```
T1: WATCH seat:A
T2: WATCH seat:A
T1: SET seat:A T1_session ← succeeds
T2: SET seat:A T2_session ← EXEC aborts (WATCH detects change)
T2: must retry
```

This works but requires the client to implement retry logic, adding latency and code complexity.

### The Lua Script Solution

Redis executes Lua scripts atomically — no other command can execute between instructions:

```lua
for i = 1, #KEYS do
    local ok = redis.call('SET', KEYS[i], ARGV[1], 'NX', 'EX', tonumber(ARGV[2]))
    if ok then
        table.insert(locked, KEYS[i])
    else
        for _, k in ipairs(locked) do redis.call('DEL', k) end
        return redis.error_reply('SEAT_TAKEN:' .. KEYS[i])
    end
end
```

Properties:
- **All-or-nothing**: partial locks are rolled back within the script
- **One round trip**: the entire operation is a single Redis command from the client's perspective
- **No client retry logic**: the script either succeeds completely or fails completely

---

## Data Model

### Redis Keys (ephemeral, TTL-based)

```
seat:{showtimeID}:{seatID}   → sessionID
  TTL present  → seat is held
  TTL absent   → seat is confirmed (PERSIST was called)

session:{sessionID}          → JSON(Session)
  Same TTL lifecycle as seat keys
```

### MongoDB Documents

**bookings** collection:
```json
{
  "_id": "uuid",
  "session_id": "uuid",
  "user_id": "string",
  "showtime_id": "string",
  "movie_id": "string",
  "seats": [{"id": "A1", "row": "A", "number": 1}],
  "status": "held|confirmed|released|expired",
  "price_cents": 3000,
  "currency": "USD",
  "created_at": "ISO8601",
  "expires_at": "ISO8601",
  "confirmed_at": "ISO8601|null"
}
```

The `expires_at` field has a **partial TTL index** that auto-deletes documents with `status` in `["held", "expired"]` after `expires_at` passes. Confirmed and released documents are retained permanently for history and analytics.

---

## Booking State Machine

```
         ┌─────────────────────────────────────────┐
         │                  HOLD                   │
         ▼                                         │
      [held] ──confirm──► [confirmed]              │
         │                                         │
         ├──release──► [released]                  │
         │                                         │
         └──TTL fires──► [expired] ─────────────────┘
                                    (Redis auto-delete)
```

State transitions are enforced by the `Booking` aggregate. Calling `Confirm()` on a non-held booking returns `ErrInvalidStatusTransition`. No external code can bypass this check.

---

## Real-Time Seat Map: The N+1 Problem

### Problem

A showtime hall has 200 seats. 50 are currently held. Checking each seat's status naively:

```
50 × (GET seat:X + TTL seat:X) = 100 Redis commands = ~100 × RTT
```

At 1ms per RTT: 100ms per seat map request. At 2-second polling with 1,000 users: 500 seat map requests/second × 100 Redis commands = 50,000 commands/second.

### Solution: 2 Pipeline Round Trips

```
Round trip 1: SCAN seat:{showtimeID}:* → collect all active seat keys
Round trip 2: Pipeline(GET key + TTL key) for all keys simultaneously
Round trip 3: Pipeline(GET session:X) for unique session IDs (HeldByMe resolution)
```

Total: 3 round trips regardless of seat count or hall size.

---

## Failure Scenarios

### Redis Unavailable

- `HoldSeats` fails with 500
- `ConfirmBooking` fails with 500
- `GetSeatMap` fails with 500
- **Recovery**: Redis restart restores state from persisted keys. Confirmed bookings (no TTL) survive restart. Held keys with TTL may be lost if Redis was not persisting to disk.
- **Improvement needed**: Redis persistence (`appendfsync always`) and Sentinel/Cluster for HA.

### MongoDB Unavailable

- `HoldSeats`: Redis locked, MongoDB write fails → compensating transaction releases Redis. Client gets 500 and can retry.
- `ConfirmBooking`: Redis confirmed (PERSIST called), MongoDB update fails → Client gets 500. Retry is safe (ConfirmSession is idempotent on an already-confirmed key).
- **Inconsistency window**: Between Redis confirm and MongoDB update failure, the booking exists in Redis as confirmed but not in MongoDB. The hold will persist in Redis permanently (no TTL) until manual cleanup or MongoDB retry succeeds.

### Both Unavailable

Both operations fail. The `must()` function in `main.go` aborts startup if either database is unreachable. In-flight requests at time of failure return 500.

---

## Layer Architecture (Clean Architecture)

```
┌─────────────────────────────────────────┐
│  interfaces/http                        │  ← Gin handlers, DTOs, middleware
│  (depends on: application, domain)      │
├─────────────────────────────────────────┤
│  application/booking, application/movie │  ← Use cases
│  (depends on: domain interfaces only)   │
├─────────────────────────────────────────┤
│  infrastructure/redis, mongodb, seeder  │  ← Concrete implementations
│  (depends on: domain interfaces)        │
├─────────────────────────────────────────┤
│  domain/booking, domain/movie           │  ← Entities, VOs, repo interfaces
│  (depends on: stdlib only)              │
└─────────────────────────────────────────┘

Dependency rule: arrows point inward only. ✅
```

---

## Trade-offs Made

| Decision | Alternative | Why This Choice |
|---|---|---|
| Redis Lua scripts | WATCH/MULTI/EXEC | No client retry logic; single round trip |
| MongoDB for bookings | PostgreSQL | Flexible schema for seat array; native TTL index |
| 2-second polling | WebSockets / SSE | Simpler implementation; SSE is the documented next step |
| In-process events | Kafka / NATS | Avoid operational overhead for v1; interface-compatible swap |
| Gin framework | Echo, stdlib net/http | Mature routing, middleware ecosystem |
| Next.js App Router | SPA + API | SSR for SEO, simple client components for real-time UI |
