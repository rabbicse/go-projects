# Cinema Booking Engine

> A production-grade, full-stack seat reservation system built to demonstrate Domain-Driven Design, Clean Architecture, and concurrent systems engineering — with the hardest problem front and centre: **atomic multi-seat locking under 10,000 concurrent goroutines**.

[![Go](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Next.js](https://img.shields.io/badge/Next.js-15-000000?logo=next.js&logoColor=white)](https://nextjs.org)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)](https://redis.io)
[![MongoDB](https://img.shields.io/badge/MongoDB-7-47A248?logo=mongodb&logoColor=white)](https://mongodb.com)
[![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-wired-000?logo=opentelemetry)](https://opentelemetry.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Why This Project Exists

Most booking demos skip the hardest question: **what happens when two users click the same seat at the same millisecond?**

This project confronts it directly. A custom Redis Lua script locks all requested seats atomically in a single command execution — **all seats are reserved, or none are** — with automatic rollback if any seat is taken. This guarantee holds under 10,000 concurrent goroutines without a single phantom booking. The proof is an integration test, not a claim.

Beyond the concurrency showcase, this is an end-to-end demonstration of:

- **DDD** with five bounded contexts, aggregate invariants, domain events, and an Anti-Corruption Layer
- **Clean Architecture** with a hard dependency rule: the domain layer has zero external imports, enforced by grep in CI
- **Event-driven patterns** using a synchronous in-process dispatcher ready to swap for NATS JetStream
- **Production observability**: OpenTelemetry → Prometheus → Grafana → Loki → Tempo, with exemplar trace links
- **Full test pyramid**: domain unit, application mock, `httptest` handler, `testcontainers-go` integration, and k6 load tests across four traffic scenarios

---

## System Overview

```
                     ┌──────────────────────────────────┐
                     │    Next.js 15 / React 19          │
                     │  App Router · TanStack Query v5   │
                     │  Tailwind v4 · shadcn/ui           │
                     └──────────────┬───────────────────┘
                                    │ /api/v1/* rewrite
                     ┌──────────────▼───────────────────┐
                     │         Go + Gin API              │
                     │                                   │
                     │  interfaces/http  (handlers, MW)  │
                     │        ↓                          │
                     │  application    (use cases)       │
                     │        ↓                          │
                     │  domain         (zero ext. deps)  │
                     │        ↓                          │
                     │  infrastructure (Redis + Mongo)   │
                     └────────────┬─────────────┬───────┘
                                  │             │
                       ┌──────────▼──┐   ┌──────▼──────┐
                       │  Redis 7    │   │  MongoDB 7   │
                       │  seat locks │   │  bookings    │
                       │  TTL expiry │   │  movies      │
                       └─────────────┘   └─────────────┘
                                  │             │
                     ┌────────────▼─────────────▼───────┐
                     │  Prometheus · Grafana · Loki      │
                     │  Tempo · AlertManager             │
                     └──────────────────────────────────┘
```

### Bounded Contexts (DDD)

The domain is split along natural business seams, each with its own ubiquitous language and no shared types across boundaries:

| Context | Aggregate roots | Integration pattern |
|---|---|---|
| **Catalog** | `Movie`, `Screening` | Published to Reservation via ACL (primitives only) |
| **Reservation** | `SeatReservation` | Emits `ReservationConfirmedEvent` → Booking context |
| **Booking** | `Booking` | Subscribes to reservation events, owns durable record |
| **Identity** *(future)* | `User` | JWT claims as shared kernel |
| **Payment** *(future)* | `Payment` | Saga-based coordination with Reservation |

### Clean Architecture Layers

```
domain/          ← zero external dependencies (enforced by CI)
  booking/       # Booking AR, SeatReservation, domain events, errors
  movie/         # Movie AR, Screening entity
  shared/        # Money VO, typed IDs, DomainEvent interface

application/     ← imports domain interfaces only
  booking/       # ReserveSeats, ConfirmReservation, ReleaseReservation, GetSeatMap
  movie/         # ListMovies, GetScreening, CreateMovie, CreateScreening

infrastructure/  ← implements domain repository interfaces
  persistence/
    redis/       # luaHold, luaConfirm, luaRelease + pipeline GET
    mongodb/     # BSON mapping, TTL indexes, cursor pagination
  seeder/        # Seeds 5 movies + 11 screenings on first boot

interfaces/http/ ← Gin handlers, DTOs, middleware stack
  handler/       # BookingHandler, MovieHandler, AdminHandler
  middleware/    # RequestID → Tracing → Metrics → Logging → CORS → RateLimit
  docs/          # Embedded swagger.json (served at /api/v1/docs/swagger.json)
```

**Dependency rule verified at build time:**
```bash
# CI assertion — fails build if domain layer imports an external package
grep -r '"github.com/' backend/internal/domain/ && exit 1 || true
```

---

## The Core Engineering Challenge

### Atomic Multi-Seat Locking

Seat reservation under concurrent load is deceptively hard. The naive approach — check availability, then book — has a race window:

```
User A: check A1=free, check A2=free ──────────────────── book A1+A2 ✓
User B: check A1=free, check A2=free ─── book A1+A2 ✓
                                          ↑ double-booking
```

Any read-then-write pattern fails. The solution must be atomic.

**Three Redis Lua scripts handle the full reservation lifecycle:**

```
Hold    →  luaHold:    SET all keys NX EX {ttl}  (all-or-none + rollback)
Confirm →  luaConfirm: PERSIST all keys           (remove TTL = permanent)
Release →  luaRelease: DEL all keys               (only if not confirmed)
```

Lua scripts run inside Redis's single-threaded command processor — no interleaving is possible. The `luaHold` script rolls back all previously locked keys atomically if any seat is already taken:

```lua
local held = {}
for i, key in ipairs(KEYS) do
    if redis.call('SET', key, ARGV[1], 'NX', 'EX', ARGV[2]) == false then
        for _, k in ipairs(held) do redis.call('DEL', k) end  -- atomic rollback
        return i   -- index of conflicting key
    end
    table.insert(held, key)
end
return 0  -- all seats locked
```

**Race conditions fixed beyond the basic Lua lock:**

| Race | Scenario | Fix |
|---|---|---|
| RC-01 | Release fires after Confirm | `luaRelease` checks `TTL == -1` (confirmed = no TTL) before DEL |
| RC-02 | TTL expires between checkout and confirm click | `luaConfirm` checks key EXISTS before PERSIST |
| RC-03 | Cleanup job deletes seats of an active screening | Cleanup only runs when `screening.end_time < now()` |

### Concurrency Proof

```go
func TestConcurrentHold_ExactlyOneWins(t *testing.T) {
    const goroutines = 10_000
    var wins atomic.Int32
    var wg sync.WaitGroup

    for i := 0; i < goroutines; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            _, err := repo.HoldSeats(ctx, screeningID, []string{"A1"}, 10*time.Minute)
            if err == nil { wins.Add(1) }
        }()
    }
    wg.Wait()

    assert.Equal(t, int32(1), wins.Load(), "exactly one goroutine must win")
}
```

Run it: `cd backend && make test-integration`

### Redis Cluster Compatibility

All seat keys use the hash tag pattern `seat:{screeningID}:{seatID}`. Redis Cluster hashes only the `{screeningID}` portion, placing all seats for a given screening in the same hash slot — a requirement for multi-key Lua scripts to work in Cluster mode.

---

## Tech Stack Rationale

| Technology | Reason for choice |
|---|---|
| **Go** | Goroutines + `sync/atomic` make concurrency testing natural. The race detector (`-race`) finds bugs the test assertions might miss. |
| **Gin** | `c.FullPath()` returns the route template, not the actual URL — critical for keeping Prometheus label cardinality bounded. |
| **Redis Lua** | Server-side atomicity without distributed locks. PERSIST/TTL idiom maps naturally to hold → confirm → expire lifecycle. |
| **MongoDB** | The booking document is a natural aggregate (seat IDs, pricing, status history always read together). No cross-booking joins needed. |
| **Next.js 15 App Router** | Server Components for catalog (zero JS for the read path). Client Components only where the booking state machine runs. |
| **TanStack Query v5** | `refetchIntervalInBackground: false` pauses seat-map polling when the tab is hidden — a correctness fix, not just an optimisation. |
| **testcontainers-go** | Real Redis 7 + MongoDB 7 per test suite. No mocking of I/O behaviour that could mask production bugs. |
| **OpenTelemetry** | Vendor-neutral. Exemplars link a P99 latency spike directly to a specific Tempo trace, and from there to Loki log lines. |
| **k6** | Native Go-like scripting. 409 Conflict responses during concurrent hold tests are classified as expected, not errors. |

---

## Getting Started

### Prerequisites

- Go 1.23+, Node.js 22+, Docker + Docker Compose
- k6 (load tests only) — [install](https://k6.io/docs/get-started/installation/)

### Option A — Run with `go run` and `npm` (no Make required)

This is the simplest way to run locally. Docker is only needed for Redis and MongoDB.

**Step 1 — start databases**

```bash
docker compose up -d redis mongo
# Redis on :6379  •  MongoDB on :27017
```

**Step 2 — run the backend**

```bash
cd backend
cp .env.example .env          # edit if needed (defaults work out of the box)
go run ./cmd/api/main.go
# API ready at http://localhost:8080
# Swagger UI:   http://localhost:8080/api/v1/docs
```

**Step 3 — run the frontend** (new terminal)

```bash
cd frontend
cp .env.local.example .env.local
npm install
npm run dev
# App ready at http://localhost:3000
```

**Default credentials**

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `admin` |

> The backend seeds 5 movies and showtimes automatically on first boot.

---

### Option B — Full stack with Docker Compose

```bash
git clone https://github.com/rabbicse/movie-ticket-booking
cd movie-ticket-booking

make up          # builds and starts everything

# Frontend:  http://localhost:3000
# API:        http://localhost:8080
# Swagger UI: http://localhost:8080/api/v1/docs
```

### Option C — Local development with Make

```bash
make dev-up      # Redis :6379 + MongoDB :27017 only

# Backend (seeds 5 movies + showtimes on first start)
cd backend && cp .env.example .env && make run

# Frontend (separate terminal)
cd frontend && cp .env.local.example .env.local && npm install && npm run dev
```

### Option D — With full observability stack

```bash
make monitoring-up   # Redis + MongoDB + Prometheus + Grafana (backend runs locally)
# or
make up              # everything including observability

# Grafana:    http://localhost:3001  (admin / admin)
# Prometheus: http://localhost:9090
```

---

## Running Tests

```bash
cd backend

make test-unit          # pure unit tests, no Docker (~5s)
make test-integration   # testcontainers, real Redis + MongoDB (~2 min)
make test               # all tests
make run-race           # unit tests with race detector

# Single test
go test -v -run TestConcurrentHold_ExactlyOneWins ./tests/integration/
go test -v -run TestBooking_Confirm ./internal/domain/booking/
```

```bash
cd frontend
npm run test            # Vitest unit tests
npm run type-check      # TypeScript only
```

### Load tests (requires k6)

```bash
make load-test-smoke        # 1 VU, 30s — sanity check
make load-test              # 50 VUs, 5 min sustained
make load-test-spike        # burst to 200 VUs
make load-test-concurrent   # 500 VUs targeting the same 120 seats
```

**Thresholds enforced:**

| Metric | Threshold |
|---|---|
| Seat hold P99 latency | < 100ms |
| Seat map P95 latency | < 50ms |
| Error rate (5xx only, excludes 409) | < 1% |

Results saved to `load-tests/results/summary.json`.

---

## API Reference

Interactive Swagger UI: `http://localhost:8080/api/v1/docs`  
Full specification: [`.claude/docs/api-design.md`](.claude/docs/api-design.md)

### Core booking flow

```
# 1. Browse
GET  /api/v1/movies
GET  /api/v1/screenings/:screeningId
GET  /api/v1/screenings/:screeningId/availability?user_id=<uuid>

# 2. Reserve (atomic, 10-min TTL)
POST /api/v1/screenings/:screeningId/reservations
     { "user_id": "uuid", "seat_ids": ["A3", "A4"] }
     → 201 { reservation_id, expires_at, total, ... }
     → 409 SEATS_UNAVAILABLE  (if any seat was taken by a concurrent request)

# 3a. Confirm payment
PUT  /api/v1/reservations/:reservationId/confirm
     → 200 { booking_id, confirmed_at, ... }

# 3b. Or release
DELETE /api/v1/reservations/:reservationId
       → 204

# 4. History
GET  /api/v1/users/:userId/bookings
```

All error responses are consistent:
```json
{ "error": { "code": "SEATS_UNAVAILABLE", "message": "...", "request_id": "req_abc" } }
```

### Admin (Basic Auth — `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars)

```
GET/POST /api/v1/admin/movies
POST     /api/v1/admin/movies/:movieId/screenings
```

---

## Observability

The three observability signals are correlated end-to-end. Click a P99 spike in Grafana → jump to the exemplar trace in Tempo → follow `trace_id` to the Loki log lines.

**SLOs alerted on:**

| SLO | Target | Alert fires after |
|---|---|---|
| API availability | 99.9% | 2 min above 1% error rate |
| Seat hold P99 | < 100ms | 3 min above threshold |
| Confirmation success rate | > 99% | 2 min with internal errors |

**Business metrics tracked:**

| Metric | Description |
|---|---|
| `booking_holds_total{result}` | Hold attempts by outcome (success / seats_unavailable / error) |
| `booking_seat_conflicts_total` | Atomic lock failures — expected during concurrent spikes |
| `booking_confirmations_total{result}` | Confirmation outcomes |
| `booking_revenue_cents_total` | Cumulative confirmed revenue |
| `booking_hold_duration_seconds` | Time between hold creation and confirm / release / expire |

Full config in [`observability/`](observability/): Prometheus scrape config, Grafana dashboard provisioning, Loki / Tempo / Promtail configs, AlertManager routing.

---

## Environment Variables

### Backend (`backend/.env.example`)

| Variable | Default | Description |
|---|---|---|
| `SERVER_PORT` | `8080` | HTTP listen port |
| `GIN_MODE` | `debug` | `debug` \| `release` |
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `REDIS_PASSWORD` | — | Redis auth password |
| `MONGODB_URI` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGODB_DATABASE` | `cinema_booking` | Database name |
| `MAX_SEATS_PER_SESSION` | `4` | Max seats per reservation |
| `HOLD_TTL` | `10m` | Reservation TTL before auto-expiry |
| `ADMIN_USERNAME` | — | BasicAuth admin username (**required**) |
| `ADMIN_PASSWORD` | — | BasicAuth admin password (**required**) |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `tempo:4317` | Tempo gRPC endpoint |
| `LOG_FORMAT` | `text` | `json` \| `text` |

### Frontend (`frontend/.env.local.example`)

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | Backend API base URL |
| `NEXT_PUBLIC_MAX_SEATS` | `4` | Max seats shown in UI (matches backend) |

---

## Design Decisions

### Why Redis for seat locking instead of MongoDB transactions?

MongoDB multi-document transactions work but add read-your-writes latency and complicate sharded deployments. Redis Lua scripts give sub-millisecond atomic operations with O(N) complexity for N seats. The trade-off: Redis is an additional operational dependency. Mitigated by using Redis Sentinel for HA, and by the fact that Redis state is ephemeral — a Redis failure degrades availability, not durability (confirmed bookings survive in MongoDB and can be used to rebuild Redis state).

### Why not Redlock?

Redlock requires ≥3 Redis instances and adds ~100ms overhead per lock (sequential writes to all nodes). For this use case — locking 1–4 specific keys per screening — a single Redis instance with Sentinel achieves the same isolation with 20× lower latency. Redlock's correctness under network partitions is also [contested](https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html).

### Why MongoDB for bookings instead of PostgreSQL?

The booking document is a natural aggregate: seat IDs, pricing, status history, and timestamps are always read and written together. No cross-booking joins exist. MongoDB's document model fits this shape. The trade-off: MongoDB's default read preference can return stale data. This is mitigated by reading seat availability from Redis (the authoritative source), not MongoDB.

### Why DDD for a booking system?

The booking domain is rich in invariants: seats can't be double-booked, a screening can't overlap another on the same screen, a held reservation must expire, a confirmed booking can't be released. These rules belong in the domain model. `booking.Confirm()` returns `ErrAlreadyConfirmed` not because a handler checked a flag, but because the aggregate enforces its own state machine — and that constraint is unit-tested independently of any framework.

### Why feature-based frontend structure?

The original `ShowtimePage.tsx` was 436 lines mixing data fetching, state management, timer logic, and rendering. A feature-based structure (`features/booking/`, `features/catalog/`, `features/admin/`) with a proper state machine (`useReducer` over a discriminated union) makes the booking flow testable, the transitions explicit, and each panel component independently renderable.

---

## Architecture Documents

All design documents are in [`.claude/`](.claude/), produced across 15 analysis phases:

| Phase | Document | Contents |
|---|---|---|
| 0 | [analysis/repository-overview.md](.claude/analysis/repository-overview.md) | Tech stack, data flow, seeded data |
| 0 | [analysis/concurrency-analysis.md](.claude/analysis/concurrency-analysis.md) | Lua correctness, N+1 Redis, 3 race conditions |
| 0 | [analysis/security-analysis.md](.claude/analysis/security-analysis.md) | 11 security findings with severity |
| 0 | [analysis/technical-debt.md](.claude/analysis/technical-debt.md) | 32 debt items, 6 priority tiers |
| 1 | [architecture/architecture-review.md](.claude/architecture/architecture-review.md) | Dependency graph, 12 anti-patterns, B- overall grade |
| 2 | [architecture/domain-model.md](.claude/architecture/domain-model.md) | 5 bounded contexts, 9 domain events, context map |
| 3 | [architecture/ddd-design.md](.claude/architecture/ddd-design.md) | Go struct sketches, PopEvents() pattern, ACL design |
| 4 | [architecture/clean-architecture.md](.claude/architecture/clean-architecture.md) | Layer definitions, DTO mapping, validation checklist |
| 5 | [tasks/backend-refactor-plan.md](.claude/tasks/backend-refactor-plan.md) | 8 milestones, 24 steps, compat bridge strategy |
| 6 | [analysis/concurrency-review.md](.claude/analysis/concurrency-review.md) | RC-01/02/03 fixes, deadlock proof, locking comparison |
| 7 | [architecture/production-architecture.md](.claude/architecture/production-architecture.md) | K8s topology, Saga pattern, 4 scaling tiers |
| 8 | [architecture/frontend-architecture.md](.claude/architecture/frontend-architecture.md) | State machine, TanStack Query, feature structure |
| 9 | [docs/api-design.md](.claude/docs/api-design.md) | Full endpoint catalog, error codes, SSE design |
| 10 | [docs/database-design.md](.claude/docs/database-design.md) | ERD, BSON schemas, index catalogue, Redis key schema |
| 11 | [docs/observability.md](.claude/docs/observability.md) | OTel setup, metrics catalogue, dashboards, alert rules |
| 12 | [docs/testing-strategy.md](.claude/docs/testing-strategy.md) | Test pyramid, 40+ missing tests, coverage targets |
| 13 | [docs/security.md](.claude/docs/security.md) | 16 findings (SEC-01–16), OWASP mapping, remediation |

---

## Roadmap

**Immediate (before any public demo):**
- [ ] Move `admin:admin` to `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars (SEC-01)
- [ ] Fix `192.168.0.50` config defaults → `localhost` (SEC-02)
- [ ] Fix fire-and-forget MongoDB write — add compensating Redis release on failure (TD-03)

**Near term (M1–M6 from [refactor plan](.claude/tasks/backend-refactor-plan.md)):**
- [ ] Bridge `domain/show.Show` → `domain/movie.Showtime` so admin-scheduled Shows drive the public booking flow (Milestone E)
- [ ] Rate limiting on booking endpoints (SEC-05)
- [ ] Pipeline `GetSeatStatuses` Redis calls (240 → 1 round trip) (TD-18)
- [ ] OpenTelemetry instrumentation end-to-end (M6)
- [ ] Rename `Showtime` → `Screening`, `Session` → `Reservation` (domain language)

**Medium term (M7–M8):**
- [ ] Idempotency-Key support on hold + confirm (double-booking on retry)
- [ ] Domain event dispatcher + `BookingConfirmedEvent` handler
- [ ] Clean up confirmed seat keys after screening ends (Redis memory leak)

**Long term:**
- [ ] JWT authentication (RS256, httpOnly cookie, refresh token)
- [ ] Server-Sent Events to replace 2s polling (~95% Redis load reduction at scale)
- [ ] NATS JetStream for cross-service domain events

---

## Quick Reference

```bash
# Backend
make run              # run locally (needs Redis + MongoDB)
make run-race         # run with race detector
make test-unit        # unit tests, no Docker
make test-integration # testcontainers (Docker required)
make test             # all tests
make lint             # golangci-lint
make build            # compile binary
make sync-swagger     # sync swagger.json to docs/
make tidy             # go mod tidy

# Frontend
npm run dev           # dev server :3000
npm run build         # production build
npm run type-check    # TypeScript check

# Docker Compose
make dev-up           # Redis + MongoDB only
make up               # everything (incl. observability)
make down             # stop all
make logs             # follow all logs

# Load tests (requires k6)
make load-test
make load-test-smoke
make load-test-spike
make load-test-concurrent
```

---

## License

MIT — see [LICENSE](LICENSE).
