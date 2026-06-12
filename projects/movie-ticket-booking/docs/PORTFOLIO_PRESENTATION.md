# Portfolio Presentation

## Cinema Booking System

**A production-shaped, full-stack seat reservation platform built to demonstrate distributed systems design, DDD, and Go engineering.**

---

## The Problem This Solves

Cinema seat reservation is a deceptively difficult engineering problem. The core challenge: thousands of users simultaneously selecting seats from a finite pool, with a 10-minute hold window and real-time UI feedback — all without overselling a single seat.

This is the same problem faced by Ticketmaster, Eventbrite, and any airline seat selection system. The naive solution (read-check-write in application code) introduces a race condition. This project solves it correctly.

---

## Technical Highlights

### 1. Atomic Multi-Seat Reservation (The Hard Part)

The booking invariant requires that either **all** selected seats are locked or **none** are — partial holds must be rolled back automatically. This is implemented via a Lua script executed atomically on the Redis server:

```lua
-- If any seat is already taken, roll back all previously locked seats
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

Two additional Lua scripts defend against race conditions that occur between the hold and confirm steps:

- **RC-01**: A `release` arriving after a `confirm` must not delete confirmed seats. Fixed by checking `TTL == -1` (confirmed keys have no TTL).
- **RC-02**: A `confirm` arriving after the hold TTL expired must fail. Fixed by checking `EXISTS` before persisting.

### 2. Clean Architecture and DDD

The codebase is organized into four layers with strict dependency inversion:

```
domain/        — Zero external dependencies. Entities, value objects, repository interfaces.
application/   — Use cases. Depends only on domain interfaces.
infrastructure/ — Concrete implementations (Redis, MongoDB).
interfaces/    — HTTP handlers, DTOs.
```

The `Booking` aggregate root enforces all state transitions. External code cannot mutate a booking's status directly — all changes go through `Confirm()`, `Release()`, `Expire()` methods that validate the transition and raise domain events.

### 3. Domain Events

Every state change produces a domain event:

```
BookingCreated → BookingConfirmed
              → BookingReleased
              → BookingExpired
```

Events are accumulated inside the aggregate and dispatched after persistence — the correct pattern for maintaining consistency between the aggregate state and the event log. An in-process dispatcher handles current consumers (logging); the architecture supports replacement with Kafka or NATS without changing the domain.

### 4. Real-Time Seat Map

The frontend polls `GET /showtimes/:id/seats?user_id=X` every 2 seconds. The backend resolves seat status using 2 Redis pipeline round trips regardless of hall size:

1. SCAN to collect active seat keys
2. Pipelined GET + TTL for all seats
3. Pipelined session lookups for HeldByMe resolution

A held seat held by the current user is highlighted green; held by others in amber; confirmed (unavailable) in red.

### 5. Observability

Prometheus metrics middleware records per-route request counts, latency histograms, and in-flight gauges using `c.FullPath()` to prevent high-cardinality labels. Grafana is auto-provisioned with Prometheus as a datasource. All logs are structured JSON (via `log/slog`) with request IDs for correlation.

---

## Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Backend | Go 1.24, Gin | Performance, strong typing, excellent concurrency primitives |
| Seat Locking | Redis 7 (Lua scripts) | Atomic multi-key operations in a single round trip |
| Persistence | MongoDB 7 | Flexible schema for booking aggregates; native TTL indexes |
| Frontend | Next.js 15 (App Router) | SSR for catalog, client-side polling for real-time seat state |
| Containers | Docker + Compose | Reproducible environments with health-checked dependencies |
| Metrics | Prometheus + Grafana | Production-grade observability from day one |
| Tests | testify, testcontainers-go, k6 | Unit → integration → load test coverage |

---

## Numbers

- **Backend startup**: ~500ms (index creation + seed check)
- **Hold latency**: ~20ms (including remote database RTT)
- **Confirm latency**: ~34ms
- **Redis operations**: 3 round trips for seat map (vs. N+1 naive)
- **Concurrency test**: `TestConcurrentHold_ExactlyOneWins` — 10 goroutines racing for 1 seat; exactly 1 succeeds

---

## What I Would Add Next

| Feature | Why |
|---|---|
| JWT authentication | Current user identity is trust-on-first-use only |
| Rate limiting | Prevent hold-and-release abuse |
| Stripe payment integration | Complete the booking lifecycle |
| Redis Sentinel | Eliminate single point of failure |
| Server-Sent Events | Replace polling with push notifications |
| OpenTelemetry | Distributed tracing across service boundaries |
