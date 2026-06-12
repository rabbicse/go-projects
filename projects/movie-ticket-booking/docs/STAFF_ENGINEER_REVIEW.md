# Staff Engineer Review

**Reviewer**: Self-assessment simulated at Staff Engineer / Principal level  
**Date**: 2026-06-10  
**Codebase**: Cinema Booking System (Go + Next.js, M1–M12)

---

## Executive Summary

This is a well-structured showcase project that demonstrates solid understanding of Clean Architecture, DDD principles, and distributed-systems concurrency patterns. The critical booking invariant (atomic multi-seat hold) is implemented correctly and thoughtfully defended against race conditions. The code is production-*shaped* but not production-*hardened* — it lacks the operational and security layers that would be required before taking real traffic.

**Overall Rating: 7.5 / 10** for a portfolio project. Genuinely strong architecture and concurrency work, meaningful gaps in auth, rate limiting, and operational resilience.

---

## 1. Code Quality

### Strengths

**Naming and readability**: Package, type, and function names are consistently clear. `SeatLockRepository`, `BookingService`, `HoldRequest`, `PopEvents()` — all self-documenting without needing comments. The `apierr.HTTPStatusFor()` function eliminates scattered `switch` blocks in handlers.

**Error hierarchy**: Domain errors are typed sentinel values (`ErrSeatAlreadyHeld`, `ErrSessionExpired`, etc.). The `errors.Is()` chain in `HTTPStatusFor` correctly handles wrapped errors. Unknown errors default to a safe 500 with a generic message — no internal detail leakage through the normal error path.

**Compensating transaction**: The `HoldSeats` service method correctly rolls back the Redis lock if the MongoDB write fails. The comment explains the _why_. This is exactly the kind of defensive thinking that separates junior from senior work.

**Lua Lua scripts**: Three atomically-correct scripts (`luaHoldSeats`, `luaConfirm`, `luaRelease`) each solve a specific race condition:
- `luaHoldSeats`: all-or-nothing seat locking
- `luaConfirm`: EXISTS guard (RC-02) prevents confirming an already-expired hold
- `luaRelease`: TTL guard (RC-01) prevents releasing an already-confirmed seat

The race condition labels (RC-01, RC-02) in comments are excellent engineering practice.

**Pipeline efficiency**: `GetSeatStatuses` reduces an N+1 Redis anti-pattern to exactly 2 pipeline round trips regardless of seat count. This is non-obvious and shows understanding of Redis connection costs.

**Graceful shutdown**: `main.go` handles `SIGINT`/`SIGTERM`, drains in-flight requests with a timeout, and defers MongoDB disconnect. Correct.

### Issues

**`_ = b.Release()` in `ReleaseBooking`** (`application/booking/service.go:149`): Error is silently discarded. `Release()` can only fail if the booking is not in `StatusHeld`, meaning the MongoDB record is already in a terminal state. This case should at least be logged at debug level for incident investigation.

**Double `time.Now()` in `Confirm()`** (`domain/booking/booking.go:87-88`): `Confirm()` calls `time.Now().UTC()` twice (once for expiry check, once for `UpdatedAt`). Under extreme scheduler pressure, the two calls could return different clock values. Should capture once: `now := time.Now().UTC()`.

**`uuid` dependency in application layer** (`application/booking/service.go:9`): The domain layer correctly avoids external deps (uses `crypto/rand` directly for ID generation). The application layer imports `github.com/google/uuid` for session IDs. This inconsistency is minor but noticeable. Either use stdlib everywhere or use a shared UUID package everywhere.

**`AllowedOrigins: []string{"*"}` hardcoded in `main.go:81`**: The CORS config accepts all origins regardless of `GIN_MODE`. In production this should be read from environment config.

**`HoldTTL int(s.holdTTL.Seconds())` conversion** (`application/booking/service.go:70`): Converting `time.Duration` → `float64` → `int` for TTL seconds. If `holdTTL` is ever set to a value > `math.MaxInt32` seconds (~68 years), this silently truncates. Not a real risk at current config but shows inconsistency vs. the typed duration in the domain.

**Validator messages exposed** (`interfaces/http/handler/booking_handler.go:25`): `ShouldBindJSON` error messages contain struct field paths. A custom validator message translator should map these to user-facing strings.

### Maintainability Assessment

| Dimension | Score | Note |
|---|---|---|
| Readability | 9/10 | Clear names, minimal comments where comments are justified |
| Consistency | 8/10 | Minor inconsistency between stdlib UUID vs google/uuid |
| Coupling | 9/10 | Dependency inversion applied correctly at all layer boundaries |
| Cohesion | 8/10 | Each package has a single clear responsibility |
| Complexity | 8/10 | Lua scripts are complex but well-commented; no business logic complexity issues |
| Testability | 6/10 | Domain and handler tests exist; application service tests are sparse; no integration test coverage for error paths |

---

## 2. Architecture Quality

### DDD Implementation

The project correctly implements the tactical DDD patterns:

**Aggregate root**: `Booking` is the aggregate root for the booking context. It owns its `Seat` value objects, controls its own state transitions (`Confirm()`, `Release()`, `Expire()`), and accumulates domain events internally. External code cannot mutate booking state directly — all transitions go through methods that enforce invariants.

**Domain events**: `BookingCreated`, `BookingConfirmed`, `BookingReleased`, `BookingExpired` are declared in the domain layer with correct base types. `PopEvents()` follows the standard "collect-and-clear" pattern. The dispatcher is in-process (not durable), which is the correct starting point for a v1.

**Value objects**: `Seat` and `shared.Money` are immutable by convention. `Money` has methods (`Multiply`, `Cents`, `Currency`) that enforce monetary arithmetic rules.

**Repository interfaces**: Declared in the domain layer (`domain/booking/repository.go`), implemented in infrastructure. Domain depends on the interface; infrastructure depends on the domain interface. Correct inversion.

**Bounded contexts**: Two bounded contexts (`booking`, `movie`) with distinct repositories. The `booking` service correctly accesses `movie.Repository` for showtime price lookup rather than embedding movie data in the booking aggregate. Cross-context access via the repository interface is acceptable at this scale.

### Remaining DDD Gaps

1. **No domain service** for complex cross-aggregate rules. `HoldSeats` in the application service touches both the Redis seat lock and MongoDB booking record. At this scale it's fine, but a `BookingPolicy` domain service would be the DDD-pure solution.

2. **Session is not a domain object**: `booking.Session` (the Redis ephemeral state) is declared in `domain/booking/repository.go` as a data struct, not a domain entity with invariants. It's mostly a DTO. Acceptable for Redis's role, but a stricter DDD implementation would model it differently.

3. **No aggregate version / optimistic locking**: `Booking.Update()` uses `ReplaceOne` with no `version` field or ETag. Concurrent updates to the same booking document could silently overwrite each other. The Redis layer protects seat reservation, but the MongoDB booking record has no concurrency control.

4. **Event dispatcher is synchronous in-process**: Domain events are dispatched synchronously in the application service. This is fine for logging but means the event handler blocks the HTTP response. A proper event bus (Kafka, NATS, even a goroutine pool) would decouple the booking flow from downstream event consumers.

### Clean Architecture Compliance

```
Domain      → no imports (only stdlib)           ✅
Application → imports domain only                ✅
Infrastructure → imports domain + stdlib         ✅
Interfaces  → imports application + domain       ✅
```

The dependency flow is correct. The one notable exception is `apierr.HTTPStatusFor` in `interfaces/http/apierr/` which imports both `domain/booking` and `domain/movie` — this is unavoidable and acceptable for the error mapping layer.

### CQRS

The project has *implicit* CQRS: `HoldSeats` / `ConfirmBooking` / `ReleaseBooking` are command paths; `GetSeatMap` / `GetUserBookings` / `ListMovies` are query paths. The separation is in naming and handler routing, but there's no explicit command/query object model. For this scale, implicit is fine.

---

## 3. What a Staff Engineer Would Flag in Code Review

1. **Missing `user_id` authentication**: Any client can claim any `user_id` in request bodies. There is no JWT or session token that ties the claimed identity to a verified principal. The authorization check (`session.UserID != userID`) protects against *accidental* cross-user access but provides no protection against deliberate impersonation.

2. **Rate limiting**: The hold endpoint has no throttle. A single automated client can hold and release seats in a tight loop, permanently blocking the hall from legitimate users.

3. **No idempotency key on hold**: If a client times out and retries `POST .../hold`, it may create two hold records for the same user. The server has no way to detect the duplicate. An `Idempotency-Key` header handled server-side would prevent this.

4. **Content-Type not enforced**: Handlers use `ShouldBindJSON` which falls back silently. Use `ShouldBindBodyWithJSON` or enforce the header in middleware.

5. **`ADMIN_PASSWORD: changeme` in `docker-compose.yml`**: Weak default shipped in SCM. Anyone who runs `make up` without changing this has an open admin endpoint.

6. **No distributed tracing**: Prometheus metrics give aggregate visibility but not per-request tracing. Adding `X-Request-ID` to error response bodies (currently headers only) and integrating OpenTelemetry would significantly reduce MTTR for production incidents.
