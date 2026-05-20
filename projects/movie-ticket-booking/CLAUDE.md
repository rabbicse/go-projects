# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Backend (Go)

```bash
cd backend

# Run locally (needs redis + mongodb running)
make run

# Unit tests (no Docker)
make test-unit

# Integration tests (Docker required — uses testcontainers-go)
make test-integration

# All tests
make test

# Build binary
make build

# Lint
make lint    # requires golangci-lint
```

### Frontend (Next.js)

```bash
cd frontend
npm install
npm run dev          # dev server on :3000
npm run build
npm run type-check   # TypeScript only
```

### Full stack via Docker Compose

```bash
make dev-up          # start Redis + MongoDB only
make up              # start everything (build + run)
make down
make logs
```

### Load tests (requires k6)

```bash
make load-test                # normal load scenario
make load-test-smoke          # quick sanity check
make load-test-spike          # burst traffic
make load-test-concurrent     # 500 VUs on same seats (Redis NX lock test)
```

## Architecture

### Backend — Clean Architecture / DDD

```
domain/          # Zero external dependencies. Entities, VOs, repo interfaces.
  booking/       # Booking aggregate (Booking, Seat VO, Session, errors)
  movie/         # Movie aggregate (Movie, Showtime entity)
  shared/        # Money value object
application/     # Use cases. Depends only on domain interfaces.
  booking/service.go   # HoldSeats, ConfirmBooking, ReleaseBooking, GetSeatMap
  movie/service.go     # ListMovies, GetShowtime
infrastructure/  # Concrete implementations.
  persistence/redis/   # Lua-script atomic multi-seat locks
  persistence/mongodb/ # Movie + Booking MongoDB repositories (v2 driver)
  seeder/              # Seeds movies + showtimes on first boot
interfaces/http/ # Gin handlers, DTOs, CORS/logger middleware
cmd/api/main.go  # Wiring: config → infra → services → router → server
```

### Key invariant — multi-seat atomic hold

`SeatLockRepository.HoldSeats` executes a Lua script via `redis.NewScript` that sets all seat keys with NX atomically. If any seat is already taken, all previously locked keys are rolled back in the same Lua call. This is the critical concurrency guarantee.

### Redis key schema

```
seat:{showtimeID}:{seatID}   →  sessionID  (TTL = held, no TTL = confirmed)
session:{sessionID}          →  JSON(Session)
```

### MongoDB collections

`movies`, `showtimes`, `bookings` — see `infrastructure/persistence/mongodb/` for BSON document structs.

### Frontend — Next.js 15 App Router

- Server components: `/app/page.tsx` (movie list), `/app/movies/[movieId]/page.tsx` (movie detail)
- Client component: `/app/showtimes/[showtimeId]/page.tsx` (seat selection + real-time polling)
- API client: `src/lib/api.ts` — all API calls go through `/api/v1/...` which Next.js rewrites to the backend
- Seat polling interval: 2 seconds (SeatGrid component)
- User identity: `crypto.randomUUID()` stored in `sessionStorage` (no auth system)

## Configuration

All backend config is via environment variables — see `backend/.env.example`.  
`MAX_SEATS_PER_SESSION` (default `4`) controls the booking limit end-to-end: enforced in `BookingService`, `BookingHandler`, and frontend UI.  
`HOLD_TTL` (default `10m`) sets Redis TTL for held sessions and MongoDB `expires_at` field.

## Testing conventions

- **Unit tests** live alongside the package they test (`booking_test.go` in `internal/domain/booking/`).
- **Integration tests** are in `tests/integration/` and use `testcontainers-go` — they need Docker.
- **Load tests** are in `load-tests/booking.js` (k6 JavaScript).
- Mock interfaces are hand-written in `_test.go` files using `testify/mock` — no generated mocks required for current tests.
- The integration test `TestConcurrentHold_ExactlyOneWins` is skipped with `-short` flag; use `make test-integration` to run it.

## Phase 2 (observability) notes

The `docker-compose.yml` contains a commented block for Prometheus + Grafana + Loki. When adding OpenTelemetry, instrument the Gin middleware in `interfaces/http/middleware/` and the Redis/MongoDB client constructors in `infrastructure/`.
