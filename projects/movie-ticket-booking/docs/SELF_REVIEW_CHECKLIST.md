# Self-Review Checklist

Engineering self-assessment as of 2026-06-10 (post M1–M12). Each item is rated **Pass**, **Partial**, or **Gap**.

---

## Architecture

| # | Check | Status | Notes |
|---|---|---|---|
| A-1 | Domain layer has zero external dependencies | ✅ Pass | `domain/` imports only stdlib. No framework, DB, or HTTP imports. |
| A-2 | Application layer depends only on domain interfaces | ✅ Pass | `application/booking/service.go` and `application/movie/service.go` use only domain interfaces. |
| A-3 | Infrastructure implements domain interfaces | ✅ Pass | `infrastructure/persistence/redis/` and `mongodb/` implement the repo interfaces declared in `domain/`. |
| A-4 | No circular dependencies between layers | ✅ Pass | Verified by successful `go build`. |
| A-5 | Concurrency critical path is atomic | ✅ Pass | Redis Lua NX script: all seats set or none. Tested by TC-025 (exactly-one-wins). |
| A-6 | Configuration is externalized | ✅ Pass | All values from env vars via `backend/internal/config/config.go`. No hardcoded production values. |
| A-7 | Service dependencies are injected, not constructed | ✅ Pass | `cmd/api/main.go` wires all dependencies explicitly. |

---

## Code Quality

| # | Check | Status | Notes |
|---|---|---|---|
| Q-1 | Domain errors are typed, not strings | ✅ Pass | `domain/booking/errors.go` defines sentinel errors (`ErrSeatsUnavailable`, `ErrInvalidStatusTransition`, etc.). |
| Q-2 | Error messages are user-friendly at the API boundary | ⚠️ Partial | High-level codes (`SEATS_UNAVAILABLE`) are good. Validator messages still expose struct field paths (F-02). Internal call-chain leaks in one place (F-04). |
| Q-3 | No panic in request handlers | ✅ Pass | Gin recovery middleware is applied. No explicit panics in handler code. |
| Q-4 | Resource cleanup on shutdown | ✅ Pass | `main.go` defers `mongoClient.Disconnect()` and `redisClient.Close()`. Graceful HTTP shutdown with context. |
| Q-5 | No hardcoded credentials in source | ✅ Pass | Admin credentials are env vars. Default `changeme` in docker-compose.yml is clearly labeled for override. |
| Q-6 | Sensitive data not logged | ✅ Pass | MongoDB URI logged only as `host:port` via `mongoHost()`. No passwords or session tokens in logs. |
| Q-7 | Consistent naming | ✅ Pass | Domain types, API DTOs, JSON fields, and MongoDB BSON fields are consistently named. |
| Q-8 | Tests cover critical path | ⚠️ Partial | Lua concurrency test and unit tests exist. No tests for HTTP handler layer or application service error paths. |

---

## API Design

| # | Check | Status | Notes |
|---|---|---|---|
| API-1 | Consistent error response shape | ✅ Pass | All errors return `{"code":"...", "message":"..."}`. No naked strings. |
| API-2 | Correct HTTP status codes | ⚠️ Partial | Standard cases correct. Missing Content-Type returns 409 instead of 400 (F-03). |
| API-3 | POST creates return 201 | ✅ Pass | Hold (`POST .../hold`) returns 201. Admin create endpoints return 201. |
| API-4 | Successful delete returns 204 | ✅ Pass | Release session returns 204 No Content. |
| API-5 | Resources identified by stable IDs | ✅ Pass | Movies use slug IDs. Sessions and showtimes use UUIDs. |
| API-6 | Pagination on list endpoints | ⚠️ Gap | `GET /movies` and `GET /users/:id/bookings` return all results. No limit/offset support. |
| API-7 | OpenAPI spec is up-to-date | ⚠️ Partial | `docs/swagger.json` exists and is served. Not verified whether all M9–M12 changes are reflected. |
| API-8 | Security headers on all responses | ✅ Pass | `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `X-Request-ID` confirmed present (TC-034). |

---

## Frontend Design

| # | Check | Status | Notes |
|---|---|---|---|
| FE-1 | Error messages propagated to UI | ✅ Pass | `ApiError` class carries `code` and `message`. Seat selection page and booking page display API error messages. |
| FE-2 | Loading states on async operations | ⚠️ Partial | Hold/confirm/release buttons disable during the call. Initial page load has no skeleton — content jumps on hydration. |
| FE-3 | Admin credentials stored securely | ✅ Pass | `sessionStorage` (not `localStorage`, not a cookie). Cleared on tab close. |
| FE-4 | No hardcoded credentials | ✅ Pass | Admin pages read token from `sessionStorage` keyed by `ADMIN_KEY`. |
| FE-5 | User identity persists within session | ✅ Pass | `crypto.randomUUID()` stored in `sessionStorage`. Consistent within a tab. |
| FE-6 | Real-time seat updates | ✅ Pass | SeatGrid polls every 2 seconds. `held_by_me` flag enables per-user coloring. |
| FE-7 | Responsive layout | ⚠️ Partial | Seat grid is a CSS grid and reflows on narrow screens. Not tested on mobile viewports. |
| FE-8 | TypeScript strict mode | ✅ Pass | `npm run type-check` passes with 0 errors. |

---

## User Experience

| # | Check | Status | Notes |
|---|---|---|---|
| UX-1 | Users can discover movies without an account | ✅ Pass | Browse flow requires no login. |
| UX-2 | Booking flow is clear and linear | ✅ Pass | Movie → Showtime → Seat map → Hold → Confirm → Booking list is unambiguous. |
| UX-3 | Users know when seats are taken | ✅ Pass | Held seats shown in amber, confirmed (unavailable) in red, user's own in green. |
| UX-4 | Booking expiry is visible | ⚠️ Gap | `expires_at` is in the hold response but no countdown is shown in the UI. Users lose seats without warning. |
| UX-5 | Demo data is usable on fresh start | ⚠️ Gap | Seeded showtimes are in the past (F-01). A fresh install shows 5 movies with expired shows. |
| UX-6 | Booking history is useful | ⚠️ Partial | History page exists and works. Does not show movie title, hall, or showtime — only seat IDs and total. |
| UX-7 | Admin can add content without engineer involvement | ✅ Pass | Admin UI allows adding movies and showtimes via web form. |

---

## Concurrency & Reliability

| # | Check | Status | Notes |
|---|---|---|---|
| C-1 | Seat hold is atomic across multiple seats | ✅ Pass | Redis Lua NX script — all or nothing. See architecture note in CLAUDE.md. |
| C-2 | Holds expire automatically | ✅ Pass | Redis TTL on hold keys. MongoDB `expires_at` field set at hold time. |
| C-3 | Confirmed bookings do not expire | ✅ Pass | `HoldSeats` sets TTL; `ConfirmBooking` calls `PERSIST` to remove TTL. |
| C-4 | No data loss on hold expiry | ✅ Pass | Session document expires from Redis; booking is never written to MongoDB until confirmation. |
| C-5 | Race condition test exists | ✅ Pass | `TestConcurrentHold_ExactlyOneWins` in integration tests (skipped with `-short`). |
| C-6 | Backend handles Redis unavailability gracefully | ⚠️ Gap | If Redis is down, hold requests return 500 with no retry or circuit breaker. Backend startup aborts if Redis is unreachable. |

---

## Performance

| # | Check | Status | Notes |
|---|---|---|---|
| P-1 | Read endpoints under 50ms (remote DB) | ✅ Pass | Movies 11ms, showtime 20ms, seat map 9.5ms. |
| P-2 | Write endpoints under 100ms (remote DB) | ✅ Pass | Hold 20ms, confirm 34ms. |
| P-3 | No N+1 queries | ✅ Pass | `GetShowtime` fetches the showtime document which embeds the seat layout. No per-seat queries. |
| P-4 | MongoDB indexes on query fields | ✅ Pass | `EnsureIndexes()` creates indexes on `showtimes.movie_id`, `bookings.user_id`, etc. |
| P-5 | Prometheus metrics present | ✅ Pass | `http_requests_total`, `http_request_duration_seconds`, `http_requests_in_flight` (TC-024). |
| P-6 | No unbounded result sets in production paths | ⚠️ Gap | `GET /movies` and `GET /users/:id/bookings` return all documents. Acceptable for demo scale, not for production. |

---

## Documentation

| # | Check | Status | Notes |
|---|---|---|---|
| D-1 | CLAUDE.md covers build, test, and run commands | ✅ Pass | All commands present with flags and options. |
| D-2 | CLAUDE.md covers architecture | ✅ Pass | Layer diagram, Redis key schema, MongoDB collections, API table all present. |
| D-3 | Running guide for new developers | ✅ Pass | `docs/RUNNING_THE_APPLICATION.md` — three setup options, config reference, troubleshooting. |
| D-4 | API documentation is served at runtime | ✅ Pass | Swagger UI at `/api/v1/docs`, JSON at `/api/v1/docs/swagger.json`. |
| D-5 | Architecture decision records | ⚠️ Gap | No ADRs. The Lua NX atomicity choice and DDD layering rationale are undocumented. |
| D-6 | Load test results documented | ⚠️ Partial | k6 commands in CLAUDE.md. No baseline results committed to the repo. |

---

## Overall Assessment

The system is **solid for a portfolio/demo project**. The core booking invariant (atomic multi-seat hold) is correctly implemented and tested. The architecture is clean and the API contract is mostly correct.

**Before a production deployment**, the following must be addressed:

1. **B-01** — Fix seeded dates (users can't use the demo)
2. **B-02** — Enforce Content-Type (API contract bug)
3. **B-05** — Payment integration (no real booking without it)
4. **B-12** — Rate limiting on hold endpoint
5. **C-6** — Circuit breaker / graceful degradation on Redis failure
