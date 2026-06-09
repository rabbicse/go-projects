# Technical Debt

_Prioritised backlog of work needed before this project is production-grade — 2026-06-08_

## Priority 1 — Breaks Production Use

| ID | Debt Item | File(s) | Effort |
|---|---|---|---|
| TD-01 | Config defaults point to `192.168.0.50` — crashes out-of-the-box | `config/config.go` | 5 min |
| TD-02 | Admin password hardcoded `admin:admin` — security hole | `interfaces/http/router.go` | 30 min |
| TD-03 | MongoDB save failure silently ignored on hold — corrupts booking state | `application/booking/service.go` | 2h |
| TD-04 | Confirmed seats never deleted from Redis — memory leak over time | `infrastructure/redis/seat_lock_repository.go` | 3h |
| TD-05 | No rate limiting — any client can exhaust Redis with hold spam | Router/middleware | 2h |

## Priority 2 — Breaks Data Integrity

| ID | Debt Item | File(s) | Effort |
|---|---|---|---|
| TD-06 | `CreateShowtime` bypasses hall-overlap domain invariant | `application/movie/service.go` | 1h |
| TD-07 | No pagination on `/users/:userId/bookings` — unbounded query | `handler/booking_handler.go`, service | 2h |
| TD-08 | `StatusExpired` never assigned — expired bookings never marked in MongoDB | `domain/booking/booking.go`, service | 3h |
| TD-09 | `Booking.ID` assigned outside aggregate — broken invariant | `domain/booking/booking.go`, service | 1h |
| TD-10 | Confirm race: Redis TTL can expire between `ExpiresAt` check and `PERSIST` call | `infrastructure/redis/seat_lock_repository.go` | 4h |

## Priority 3 — Maintainability & Extensibility

| ID | Debt Item | File(s) | Effort |
|---|---|---|---|
| TD-11 | `Session` struct in domain package — infra concern leaking into domain | `domain/booking/repository.go` | 4h (requires interface refactor) |
| TD-12 | `SeatStatus` has JSON struct tags in domain — presentation in domain | `domain/booking/seat.go` | 2h |
| TD-13 | No domain events — status transitions can't be extended without modifying service | All service files | 6h |
| TD-14 | No request ID in logs — tracing impossible | `interfaces/http/middleware/logger.go` | 2h |
| TD-15 | `maxSeats` validation duplicated in handler and service | handler + service | 30 min |
| TD-16 | `Money.Add` panics on currency mismatch | `domain/shared/money.go` | 30 min |
| TD-17 | `ShowtimePrice` method belongs on MovieService, not BookingService | `application/booking/service.go` | 1h |

## Priority 4 — Performance

| ID | Debt Item | File(s) | Effort |
|---|---|---|---|
| TD-18 | `GetSeatStatuses` N+1: one Redis GET per held seat for HeldByMe check | `infrastructure/redis/seat_lock_repository.go` | 4h |
| TD-19 | SCAN per seat-map request — O(keyspace) per poll at 2s intervals | same | (part of TD-18) |
| TD-20 | No connection pool tuning on MongoDB client | `infrastructure/persistence/mongodb/client.go` | 1h |
| TD-21 | Frontend polls unconditionally every 2s — no pause on tab hidden | `components/SeatGrid.tsx` | 2h |

## Priority 5 — Frontend Architecture

| ID | Debt Item | File(s) | Effort |
|---|---|---|---|
| TD-22 | `ShowtimePage` 436-line god component — untestable | `app/showtimes/[showtimeId]/page.tsx` | 1 day |
| TD-23 | No state management (TanStack Query) — manual polling and no cache | All client pages | 1-2 days |
| TD-24 | User ID in `sessionStorage` — lost on refresh, breaks in-flight bookings | `ShowtimePage` | 2h |
| TD-25 | `PAYMENT_TTL_S = 180` hardcoded, not tied to backend `HOLD_TTL` | `ShowtimePage` | 1h |
| TD-26 | Admin auth in `localStorage` — XSS-vulnerable | `app/admin/` | 1 day |
| TD-27 | Zero frontend tests | All frontend | 2-3 days |
| TD-28 | No error boundaries — unhandled errors crash silently | All client pages | 1h |

## Priority 6 — Documentation & Developer Experience

| ID | Debt Item | File(s) | Effort |
|---|---|---|---|
| TD-29 | Seeder uses external TMDB URLs — breaks in air-gapped env | `infrastructure/seeder/seeder.go` | 1h |
| TD-30 | `SERVER_READ_TIMEOUT` / `SERVER_WRITE_TIMEOUT` missing from README env table | `README.md` | 15 min |
| TD-31 | No OpenTelemetry instrumentation despite docker-compose stubs | Multiple | 3-5 days |
| TD-32 | No structured error type — frontend matches on error strings | `domain/booking/errors.go` | 3h |

---

## Aggregate Debt by Category

| Category | Items | Estimated Effort |
|---|---|---|
| Critical bugs / security | TD-01 to TD-05 | ~8h |
| Data integrity | TD-06 to TD-10 | ~11h |
| Architecture / DDD | TD-11 to TD-17 | ~16h |
| Performance | TD-18 to TD-21 | ~8h |
| Frontend | TD-22 to TD-28 | ~1 week |
| DevEx / Docs | TD-29 to TD-32 | ~1 day |

**Total estimated**: ~4 weeks of focused engineering to reach production-grade.
