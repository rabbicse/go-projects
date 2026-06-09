# Backend Analysis

_Based on full source read of `backend/internal/` — 2026-06-08_

## Layer Compliance Assessment

### Domain Layer (`internal/domain/`) ✅ Good

- Zero external imports (only stdlib). Clean.
- `Booking` is a proper aggregate root with lifecycle methods (`Confirm()`, `Release()`).
- `Seat` is a well-formed value object: immutable, validates format on construction.
- `Money` is an immutable VO with cents + currency. Encapsulation is correct.
- `Showtime` is an entity owned by `Movie` aggregate, not a standalone root. Correct.
- `Movie.AddShowtime()` enforces hall overlap invariant. Good invariant placement.
- Repository interfaces defined in domain — infrastructure depends inward. Correct.

**Domain issues:**
- `Money.Add()` panics on currency mismatch instead of returning an error. Panics in domain logic are dangerous.
- `Session` struct lives in `domain/booking` but is really Redis ephemeral state — it leaks infrastructure concern into domain.
- `StatusExpired` constant declared but never set by any code path. Dead constant.
- `Booking.ID` is empty at construction (set by service after `booking.New()`) — aggregate should own its ID.

### Application Layer (`internal/application/`) ✅ Mostly Good

- Services depend only on domain interfaces. Dependency inversion is respected.
- Error wrapping with `fmt.Errorf("%w")` is consistent.
- `HoldSeats` validates seat format before touching Redis — correct fail-fast.
- `ShowtimePrice()` method on BookingService is a query — not a use case method. Should be on MovieService.

**Application issues:**
1. **Fire-and-forget MongoDB save on hold**: `bookingRepo.Save()` failure is only `slog.Warn`-ed, not propagated. If MongoDB is down, holds succeed but no booking record is persisted. On confirmation the `FindBySessionID` will then fail.
2. **Same fire-and-forget on confirm update**: `bookingRepo.Update()` failure is silently swallowed. Redis is confirmed but MongoDB stays as "held".
3. **`maxSeats` validation duplicated**: checked in both `BookingHandler` (handler layer) and `BookingService` (application layer). Handler check is redundant — service should be the authority.
4. **`CreateShowtime` bypasses domain invariant**: `MovieService.CreateShowtime()` calls `repo.SaveShowtime()` directly without loading the `Movie` aggregate and calling `Movie.AddShowtime()`. The hall-overlap check is therefore skipped for admin-created showtimes.
5. **No command/query separation**: all operations are on one `Service` struct. Read operations (GetSeatMap, GetUserBookings) mix with write operations.

### Infrastructure Layer (`internal/infrastructure/`) ✅ Strong

- Lua scripts for atomicity are the right approach.
- Three Lua scripts: `luaHoldSeats`, `luaConfirm`, `luaRelease` — all correct.
- `redis.NewScript()` evaluates lazily and caches the SHA — efficient.
- MongoDB v2 driver used correctly; indexes created on startup.
- BSON mapping structs (e.g., `bookingDoc`) properly isolated from domain types.
- `EnsureIndexes()` is idempotent (MongoDB ignores duplicate index creation).
- `FindByUserID` sorts by `created_at DESC` — correct default.

**Infrastructure issues:**
1. **`GetSeatStatuses` SCAN + N+1 Redis calls**: for each held seat, it calls `GetSession()` to resolve `HeldByMe`. That's one extra `GET` per held seat. Under high load with many concurrent holds, this becomes O(held_seats) round trips. For a showtime with 80 seats all held, that's 80+ Redis round trips per seat-map request (which polls every 2 seconds per client).
2. **SCAN cursor hardcoded to 0**: `r.rdb.Scan(ctx, 0, pattern, 0)` starts a fresh SCAN each call. The `.Iterator()` handles pagination internally — this is fine, but it means a full key-space scan for every seat-map request.
3. **Config defaults point to developer's LAN IP**: `192.168.0.50:6379` and `192.168.0.50:27017` — will fail out-of-the-box for any other developer. Should be `localhost`.
4. **No connection pool configuration** on MongoDB client beyond defaults.
5. **Seeder uses external TMDB image URLs** — will break if network is unavailable or TMDB CDN changes URLs.

### Interface Layer (`internal/interfaces/http/`) ✅ Good

- Handler → DTO → Service separation is clean.
- `errors.Is()` used for domain error mapping to HTTP status codes.
- `gin.Recovery()` middleware installed — panics won't crash the server.
- Structured JSON logging via `log/slog` in middleware.

**Interface issues:**
1. **Admin credentials hardcoded in router**: `gin.BasicAuth(gin.Accounts{"admin": "admin"})`. No configuration.
2. **No rate limiting middleware** — any IP can spam hold requests.
3. **No request ID injection** — logger doesn't generate/propagate a request ID, so distributed tracing is impossible.
4. **`ReleaseBooking` handler reads body for `user_id`** but HTTP DELETE with a body is unusual — query param or header would be more conventional.
5. **No pagination on `GetUserBookings`** — returns all bookings for a user unbounded.
6. **CORS wildcard**: `AllowedOrigins: []string{"*"}` passed from main — exposes all origins.
7. **`SeatStatus` VO defined in `domain/booking`** but contains presentation fields (`HeldByMe`, `ExpiresAt *int64`) that are only meaningful for the HTTP response — leaks HTTP concerns into domain.

## Error Handling Pattern

Consistent sentinel errors in `domain/booking/errors.go`. Service wraps with `fmt.Errorf`. Handler unwraps with `errors.Is`. This is the correct Go pattern.

**Gap**: No structured error type with a machine-readable code. All errors are plain strings. Frontend has to match on error message strings for display logic.

## Configuration

`caarlos0/env/v11` is a solid choice. Config struct is well-organized into sub-structs. All timeouts are configurable.

**Gap**: `SERVER_READ_TIMEOUT` and `SERVER_WRITE_TIMEOUT` documented in code but absent from `README.md` environment variable table.

## Logging

`log/slog` JSON handler at INFO level. Request logger middleware captures method, path, status, latency, IP. Service layer logs warnings for non-fatal errors.

**Gap**: No request ID field in log entries. No span/trace IDs. No log sampling for high-volume endpoints.

## Module Details

Module path: `github.com/rabbicse/movie-ticket-booking`  
Go version: 1.24  
Key dependencies: `gin-gonic/gin`, `redis/go-redis/v9`, `mongo-driver/v2`, `google/uuid`, `caarlos0/env/v11`, `testify`, `testcontainers-go`
