# Repository Overview

_Generated: 2026-06-08. Do not delete — consumed by downstream analysis docs._

## What This Project Is

A full-stack cinema ticket booking platform. The primary engineering showcase is **atomic multi-seat locking under concurrent load** (Redis Lua scripts, tested at 10 000 VUs). It is also used as a portfolio piece demonstrating DDD + Clean Architecture in Go.

## Repository Layout

```
movie-ticket-booking/
├── backend/           Go 1.24 Gin API (Clean Architecture / DDD)
├── frontend/          Next.js 15 / React 19 App Router
├── load-tests/        k6 JavaScript scenarios
├── docker-compose.yml Redis + MongoDB + app containers
├── Makefile           Root-level orchestration targets
└── CLAUDE.md          Developer quick-start
```

## Technology Stack

| Layer | Technology |
|---|---|
| Go backend | Gin, `log/slog`, `caarlos0/env`, `google/uuid` |
| Cache / lock | Redis 7 (`redis/go-redis/v9`), Lua scripting |
| Database | MongoDB (`mongo-driver/v2`) |
| Frontend | Next.js 15 App Router, React 19, TypeScript |
| Testing | `testify`, `testcontainers-go`, k6 |
| Infra | Docker Compose |

## Backend Package Inventory

| Package | Path | Role |
|---|---|---|
| `config` | `internal/config/` | Env-based config via `caarlos0/env` |
| `domain/booking` | `internal/domain/booking/` | Booking aggregate, Seat VO, Session, repository interfaces |
| `domain/movie` | `internal/domain/movie/` | Movie aggregate, Showtime entity, repository interface |
| `domain/shared` | `internal/domain/shared/` | Money VO |
| `application/booking` | `internal/application/booking/` | HoldSeats, ConfirmBooking, ReleaseBooking, GetSeatMap, GetUserBookings |
| `application/movie` | `internal/application/movie/` | ListMovies, GetMovie, GetShowtime, CreateMovie, CreateShowtime |
| `infrastructure/redis` | `internal/infrastructure/persistence/redis/` | Lua seat-lock implementation |
| `infrastructure/mongodb` | `internal/infrastructure/persistence/mongodb/` | Movie + Booking repositories |
| `infrastructure/seeder` | `internal/infrastructure/seeder/` | Seeds 5 movies + 11 showtimes on first boot |
| `interfaces/http` | `internal/interfaces/http/` | Router, handlers (Movie, Booking, Admin), DTOs, CORS/logger middleware |
| `docs` | `internal/docs/` | Embedded OpenAPI spec served at `/api/v1/docs/swagger.json` |

## Data Flow (Happy Path — Hold → Confirm)

```
Browser → POST /api/v1/showtimes/:id/hold
  → BookingHandler.HoldSeats
    → BookingService.HoldSeats
      → MovieRepo.FindShowtime (MongoDB — validate showtime exists)
      → SeatLockRepo.HoldSeats (Redis Lua — atomic NX lock all seats)
      → BookingRepo.Save (MongoDB — persist "held" record)
    ← Session{sessionID, expiresAt}
  ← 201 {session_id, expires_at}

Browser → PUT /api/v1/sessions/:id/confirm
  → BookingHandler.ConfirmBooking
    → BookingService.ConfirmBooking
      → SeatLockRepo.GetSession (Redis)
      → BookingRepo.FindBySessionID (MongoDB)
      → booking.Confirm() (domain invariant check)
      → SeatLockRepo.ConfirmSession (Redis Lua — PERSIST removes TTL)
      → BookingRepo.Update (MongoDB — status = confirmed)
    ← Booking
  ← 200 BookingResponse
```

## Key Numbers

| Parameter | Default | Env var |
|---|---|---|
| Max seats per session | 4 | `MAX_SEATS_PER_SESSION` |
| Hold TTL | 10 minutes | `HOLD_TTL` |
| Payment window (frontend only) | 3 minutes | hardcoded `PAYMENT_TTL_S = 180` |
| Seat poll interval | 2 seconds | hardcoded in `SeatGrid.tsx` |
| k6 concurrency test | 10 000 goroutines, 1 seat | `TestConcurrentHold_ExactlyOneWins` |

## Seeded Data

5 movies (Dune 2, Oppenheimer, Inception, The Batman, Interstellar), 11 showtimes across 3 halls (Hall A: 8×10=80 seats, Hall B: 6×8=48 seats, Hall C: 10×12=120 seats). Prices USD 10.00–16.00.

## Booking Lifecycle

```
StatusHeld → StatusConfirmed   (via Confirm())
StatusHeld → StatusReleased    (via Release())
StatusHeld → StatusExpired     (logical — Redis TTL expiry; MongoDB record not auto-updated)
```

Note: `StatusExpired` exists as a constant but is never set programmatically. Expired sessions are detected by checking `ExpiresAt` at confirm-time and by Redis TTL eviction.
