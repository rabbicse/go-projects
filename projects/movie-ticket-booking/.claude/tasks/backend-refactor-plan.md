# Backend Refactoring Plan

_Phase 5 — Incremental migration steps — 2026-06-09_  
_Builds on: clean-architecture.md (Phase 4), ddd-design.md (Phase 3)_

---

## Guiding Constraints

1. **Never break the running system** — the API must respond correctly after every step
2. **Tests must pass after every step** — `make test-unit` is the gate
3. **One concern per commit** — each step is independently reviewable
4. **No big-bang rewrite** — each step is at most 1–3 hours of work
5. **Architecture validation checklist** (from Phase 4) must pass before milestone completion

---

## Migration Overview

```
M1  Quick Wins          (1–2h)  — zero-risk isolated fixes
M2  Shared Kernel       (2–3h)  — foundation types needed by all layers
M3  Domain Hardening    (3–4h)  — fix aggregates without moving files
M4  Package Rename      (2–3h)  — rename packages; move misplaced types
M5  Application Layer   (4–6h)  — commands/queries, event dispatch, service split
M6  Infrastructure      (3–4h)  — rename repos, fix N+1, add cleanup
M7  Interface Layer     (3–4h)  — DTOs, middleware, error mapping
M8  Verification        (1–2h)  — full test pass + load test
```

**Total estimated effort**: 19–28 hours of focused engineering.

---

## Milestone 1 — Quick Wins

_No architecture changes. These are isolated bug/security fixes. Do these first — they carry zero risk and make the codebase safer for deeper work._

---

### Step 1.1 — Fix config defaults (5 min)

**File**: `backend/internal/config/config.go`

```go
// Before
Addr: string `env:"REDIS_ADDR" envDefault:"192.168.0.50:6379"`
URI:  string `env:"MONGODB_URI" envDefault:"mongodb://192.168.0.50:27017"`

// After
Addr: string `env:"REDIS_ADDR" envDefault:"localhost:6379"`
URI:  string `env:"MONGODB_URI" envDefault:"mongodb://localhost:27017"`
```

**Verify**: `cp .env.example .env && make run` starts without connection errors.

---

### Step 1.2 — Read admin credentials from env (30 min)

**File**: `backend/internal/config/config.go` — add `AdminConfig`:
```go
type AdminConfig struct {
    User     string `env:"ADMIN_USER"     envDefault:"admin"`
    Password string `env:"ADMIN_PASSWORD" envDefault:"changeme"`
}
```

**File**: `backend/.env.example` — add:
```
ADMIN_USER=admin
ADMIN_PASSWORD=changeme
```

**File**: `backend/internal/interfaces/http/router.go`:
```go
// Before
admin := api.Group("/admin", gin.BasicAuth(gin.Accounts{"admin": "admin"}))

// After — RouterConfig gains AdminUser/AdminPassword fields
type RouterConfig struct {
    AllowedOrigins []string
    MaxSeats       int
    AdminUser      string
    AdminPassword  string
}
// ...
admin := api.Group("/admin", gin.BasicAuth(gin.Accounts{cfg.AdminUser: cfg.AdminPassword}))
```

**File**: `backend/cmd/api/main.go` — pass `AdminUser`/`AdminPassword` from cfg.

**Verify**: `make test-unit` passes. Admin endpoint returns 401 without credentials.

---

### Step 1.3 — Suppress sensitive values from startup log (15 min)

**File**: `backend/internal/config/config.go`:
```go
// Before
slog.Info("config loaded",
    "redis_addr",  cfg.Redis.Addr,
    "mongodb_uri", cfg.MongoDB.URI,   // ← may contain password
    ...
)

// After — log host only, never full URI
mongoHost := extractHost(cfg.MongoDB.URI)
slog.Info("config loaded",
    "server_port", cfg.Server.Port,
    "redis_addr",  cfg.Redis.Addr,
    "mongo_host",  mongoHost,
    "max_seats",   cfg.Booking.MaxSeatsPerSession,
    "hold_ttl",    cfg.Booking.HoldTTL,
)
```

**Verify**: `make run` log output contains no password-bearing URIs.

---

### Step 1.4 — Remove maxSeats check from handler (30 min)

**File**: `backend/internal/interfaces/http/handler/booking_handler.go`

Remove the duplicated check (lines 29–31). The service is already the authority. Add a comment to explain why it's absent.

**Verify**: `make test-unit` passes. `POST /hold` with too many seats still returns 400 (service validates).

---

## Milestone 2 — Shared Kernel

_Create the foundation types used by all bounded contexts. These are new files — zero breakage risk._

---

### Step 2.1 — Create `internal/shared` package (45 min)

Create the following new files:

**`backend/internal/shared/events.go`**:
```go
package shared

import "time"

type DomainEvent interface {
    EventName() string
    OccurredAt() time.Time
}

type EventBase struct {
    Name string
    At   time.Time
}
func (e EventBase) EventName() string     { return e.Name }
func (e EventBase) OccurredAt() time.Time { return e.At }
```

**`backend/internal/shared/user_id.go`**:
```go
package shared

import (
    "errors"
    "strings"
)

type UserID struct{ value string }

func NewUserID(v string) (UserID, error) {
    v = strings.TrimSpace(v)
    if v == "" { return UserID{}, errors.New("user ID cannot be empty") }
    return UserID{value: v}, nil
}

func MustUserID(v string) UserID {
    id, err := NewUserID(v)
    if err != nil { panic(err) }
    return id
}

func (u UserID) String() string { return u.value }
func (u UserID) IsZero() bool   { return u.value == "" }
```

**`backend/internal/shared/pagination.go`**:
```go
package shared

type Pagination struct {
    Page     int
    PageSize int
}

func DefaultPagination() Pagination { return Pagination{Page: 1, PageSize: 20} }
func (p Pagination) Offset() int {
    if p.Page < 1 { return 0 }
    return (p.Page - 1) * p.PageSize
}
func (p Pagination) Limit() int {
    if p.PageSize <= 0 { return 20 }
    if p.PageSize > 100 { return 100 }
    return p.PageSize
}
```

**Verify**: `go build ./internal/shared/...` passes. Zero imports of non-stdlib packages.

---

### Step 2.2 — Fix `Money.Add` panic → error (30 min)

**File**: `backend/internal/domain/shared/money.go` → move to `backend/internal/shared/money.go`

```go
// Before
func (m Money) Add(other Money) Money {
    if m.currency != other.currency {
        panic("cannot add money of different currencies")
    }
    return Money{cents: m.cents + other.cents, currency: m.currency}
}

// After
func (m Money) Add(other Money) (Money, error) {
    if m.currency != other.currency {
        return Money{}, fmt.Errorf("cannot add %s and %s", m.currency, other.currency)
    }
    return Money{cents: m.cents + other.cents, currency: m.currency}, nil
}
```

Update all callers (currently only `Money.Multiply` doesn't use `Add`; verify no other callers):
```bash
grep -r "\.Add(" ./internal/ --include="*.go"
```

**Verify**: `make test-unit` passes. `grep -r "panic" ./internal/shared/` returns nothing.

---

### Step 2.3 — Write shared kernel tests (30 min)

**`backend/internal/shared/money_test.go`**:
```go
func TestMoney_Add_SameCurrency(t *testing.T)
func TestMoney_Add_DifferentCurrency_Error(t *testing.T)
func TestMoney_Multiply(t *testing.T)
```

**`backend/internal/shared/user_id_test.go`**:
```go
func TestNewUserID_Empty_Error(t *testing.T)
func TestNewUserID_Valid(t *testing.T)
```

**Verify**: `go test ./internal/shared/...` 100% pass.

---

## Milestone 3 — Domain Layer Hardening

_Fix aggregate invariants in-place. No package moves yet. Tests must pass throughout._

---

### Step 3.1 — Self-assign Booking ID in constructor (30 min)

**File**: `backend/internal/domain/booking/booking.go`

```go
// Add import "github.com/google/uuid"

func New(sessionID, userID, showtimeID, movieID string,
    seats []Seat, pricePerSeat shared.Money, holdTTL time.Duration) (Booking, error) {
    if len(seats) == 0 { return Booking{}, ErrNoSeatsSelected }
    now := time.Now().UTC()
    return Booking{
        ID:         uuid.New().String(),   // ← self-assigned, was set by service
        SessionID:  sessionID,
        // ... rest unchanged
    }, nil
}
```

**File**: `backend/internal/application/booking/service.go` — remove the line:
```go
b.ID = uuid.New().String()   // ← DELETE THIS LINE
```

**Verify**: `make test-unit` passes. Integration tests pass.

---

### Step 3.2 — Add `Expire()` method to Booking (20 min)

**File**: `backend/internal/domain/booking/booking.go`:
```go
func (b *Booking) Expire() error {
    if b.Status != StatusHeld {
        return ErrInvalidStatusTransition
    }
    b.Status = StatusExpired
    b.UpdatedAt = time.Now().UTC()
    return nil
}
```

**File**: `backend/internal/domain/booking/booking_test.go` — add:
```go
func TestBooking_Expire_FromHeld(t *testing.T)
func TestBooking_Expire_AlreadyConfirmed_Error(t *testing.T)
```

**Verify**: `make test-unit` passes.

---

### Step 3.3 — Add domain event scaffolding to Booking (45 min)

**File**: `backend/internal/domain/booking/booking.go` — add event collection:
```go
type Booking struct {
    // ... existing fields ...
    events []shared.DomainEvent   // unexported
}

func (b *Booking) PopEvents() []shared.DomainEvent {
    evts := b.events
    b.events = nil
    return evts
}
```

Update `New()`, `Confirm()`, `Release()`, `Expire()` to append to `b.events`.

Add event types in **`backend/internal/domain/booking/events.go`**:
```go
package booking

import "github.com/rabbicse/movie-ticket-booking/internal/shared"

type BookingCreated   struct { shared.EventBase; SessionID, UserID, ShowtimeID string }
type BookingConfirmed struct { shared.EventBase; SessionID, UserID string; TotalCents int64 }
type BookingCancelled struct { shared.EventBase; SessionID string }
type BookingExpired   struct { shared.EventBase; SessionID string }
```

**Verify**: `make test-unit` passes. `PopEvents()` returns correct events in correct order.

---

### Step 3.4 — Fix `CreateShowtime` to enforce domain invariant (45 min)

**File**: `backend/internal/application/movie/service.go`:

```go
// Before — bypasses Movie.AddShowtime()
func (s *Service) CreateShowtime(ctx context.Context, st movie.Showtime) error {
    if _, err := s.repo.FindByID(ctx, st.MovieID); err != nil {
        return fmt.Errorf("movie %s not found: %w", st.MovieID, err)
    }
    return s.repo.SaveShowtime(ctx, st)
}

// After — loads aggregate, calls domain method, saves
func (s *Service) CreateShowtime(ctx context.Context, st movie.Showtime) error {
    m, err := s.repo.FindByID(ctx, st.MovieID)
    if err != nil {
        return fmt.Errorf("movie %s not found: %w", st.MovieID, err)
    }
    if err := m.AddShowtime(st); err != nil {
        return err  // hall overlap error propagated
    }
    return s.repo.SaveShowtime(ctx, st)
}
```

**File**: `backend/internal/domain/movie/movie.go` — add `errors` to imports (already there).

**Verify**: `make test-unit` passes. Attempting to create two overlapping showtimes for the same hall returns an error.

---

### Step 3.5 — Fix fire-and-forget MongoDB save in HoldSeats (1h)

**File**: `backend/internal/application/booking/service.go`:

```go
// Before — ignores MongoDB failure
if saveErr := s.bookingRepo.Save(ctx, b); saveErr != nil {
    slog.Warn("failed to persist held booking", "error", saveErr)
}
return session, nil

// After — release Redis lock on MongoDB failure (compensating action)
if saveErr := s.bookingRepo.Save(ctx, b); saveErr != nil {
    // Compensate: release the Redis lock we just acquired
    if releaseErr := s.seatLock.ReleaseSession(ctx, sessionID); releaseErr != nil {
        slog.Error("failed to release seats after mongodb save failure",
            "session_id", sessionID, "error", releaseErr)
    }
    return booking.Session{}, fmt.Errorf("persist booking: %w", saveErr)
}
```

Apply the same pattern to `ConfirmBooking`:
```go
// Before — silently swallows MongoDB update failure
if err := s.bookingRepo.Update(ctx, b); err != nil {
    slog.Warn("failed to update booking status in mongodb", ...)
}

// After — return error so handler can respond with 500
if err := s.bookingRepo.Update(ctx, b); err != nil {
    return booking.Booking{}, fmt.Errorf("update booking record: %w", err)
}
```

**Verify**: `make test-unit` passes. Integration test: `TestHoldSeats_MongoFailure_ReleasesRedis` (new test to add).

---

## Milestone 4 — Package Restructuring

_Move and rename packages. This is the riskiest milestone — do carefully with full test runs between steps._

**Before starting M4**: Run `make test` (all tests green). Commit M1–M3 changes.

---

### Step 4.1 — Create `internal/domain/catalog` package (1h)

Create new package by copying + renaming from `domain/movie`:

1. Create `backend/internal/domain/catalog/` directory
2. Copy `domain/movie/movie.go` → `domain/catalog/movie.go`, change `package movie` → `package catalog`, rename `Showtime` → `Screening` throughout
3. Copy `domain/movie/repository.go` → `domain/catalog/repository.go`, update interface to use `Screening`
4. Create `domain/catalog/errors.go` with renamed errors
5. **Keep `domain/movie/` in place for now** — update it to be a thin alias package that re-exports catalog types:

```go
// domain/movie/compat.go — temporary bridge during migration
package movie
import "github.com/rabbicse/movie-ticket-booking/internal/domain/catalog"
type Movie = catalog.Movie
type Showtime = catalog.Screening          // alias
type Repository = catalog.Repository
var ErrMovieNotFound = catalog.ErrMovieNotFound
```

This lets existing code compile without changes while the catalog package stabilises.

6. Update `application/movie/service.go` imports → `domain/catalog`
7. Update `infrastructure/persistence/mongodb/movie_repository.go` → `domain/catalog`
8. Remove the `compat.go` bridge once all importers are updated

**Verify**: `make test-unit && make test-integration` both pass.

---

### Step 4.2 — Create `internal/domain/reservation` package (1.5h)

The `Session` struct in `domain/booking` becomes `SeatReservation` aggregate in `domain/reservation`.

1. Create `backend/internal/domain/reservation/` with:
   - `reservation.go` — `SeatReservation` aggregate (from ddd-design.md)
   - `seat.go` — `ReservedSeat` VO (copy from `domain/booking/seat.go`)
   - `status.go` — `ReservationStatus` enum
   - `events.go` — `SeatsReserved`, `ReservationConfirmed`, `ReservationReleased`, `ReservationExpired`
   - `errors.go` — renamed from `domain/booking/errors.go` subset
   - `repository.go` — `Repository` interface (replaces `SeatLockRepository`)

2. Move `SeatAvailability` (was `SeatStatus`) from `domain/booking/seat.go` to `domain/reservation/repository.go`:
```go
// No json tags — fixes SM-05
type SeatAvailability struct {
    SeatID       string
    Status       ReservationStatus
    ReservedByMe bool
    ExpiresAt    *time.Time        // domain type, not int64 — fixes unix leakage
}
```

3. Add compat alias in `domain/booking`:
```go
// domain/booking/compat.go — temporary
type Session = reservation.SeatReservation
type SeatLockRepository = reservation.Repository
```

**Verify**: `make test-unit` passes.

---

### Step 4.3 — Update `SeatLockRepository` → `SeatReservationRepository` in infra (45 min)

**File**: `backend/internal/infrastructure/persistence/redis/seat_lock_repository.go`

1. Rename struct: `SeatLockRepository` → `SeatReservationRepository`
2. Change implemented interface: `booking.SeatLockRepository` → `reservation.Repository`
3. Update method signatures to use `reservation.SeatReservation` instead of `booking.Session`
4. Update `SeatAvailability` return type
5. Update `infrastructure/redis/client.go` constructor name
6. Update `cmd/api/main.go` to use new name

**Verify**: `make test-unit && make test-integration` pass.

---

### Step 4.4 — Remove compat alias packages (30 min)

Once all importers have been updated:
1. Delete `domain/booking/compat.go`
2. Delete `domain/movie/compat.go` (if created)
3. Run `go build ./...` — fix any remaining import errors

**Verify**: `go build ./...` passes. `grep -r "compat" ./internal/` returns nothing.

---

## Milestone 5 — Application Layer Refactoring

---

### Step 5.1 — Create `application/reservation` package (1.5h)

Extract reservation use cases from `application/booking/service.go` into a new `application/reservation/service.go`.

1. Create `backend/internal/application/reservation/`
2. Create `commands.go` with `ReserveSeatsCommand`, `ConfirmReservationCommand`, `CancelReservationCommand`
3. Create `queries.go` with `GetAvailabilityQuery`
4. Create `service.go` — `HoldSeats` → `ReserveSeats`, `ConfirmBooking` → `ConfirmReservation`, `ReleaseBooking` → `CancelReservation`, `GetSeatMap` → `GetAvailability`
5. Service depends on `reservation.Repository` (Redis) + `catalog.Repository` (ACL for price lookup)

```go
// application/reservation/service.go

type Service struct {
    repo        reservationdomain.Repository
    catalogRepo catalogdomain.Repository
    maxSeats    int
    holdTTL     time.Duration
}

func (s *Service) ReserveSeats(ctx context.Context, cmd ReserveSeatsCommand) (reservationdomain.SeatReservation, error) {
    if len(cmd.SeatIDs) == 0        { return ..., reservation.ErrNoSeatsSelected }
    if len(cmd.SeatIDs) > s.maxSeats { return ..., reservation.ErrMaxSeatsExceeded }

    for _, id := range cmd.SeatIDs {
        if _, err := reservationdomain.NewReservedSeat(id); err != nil {
            return ..., fmt.Errorf("invalid seat %q: %w", id, err)
        }
    }

    // ACL: read screening from catalog context
    screening, err := s.catalogRepo.FindScreening(ctx, cmd.ScreeningID)
    if err != nil { return ..., fmt.Errorf("screening not found: %w", err) }

    seats := buildReservedSeats(cmd.SeatIDs)
    r, err := reservationdomain.New(cmd.UserID, cmd.ScreeningID, seats, s.holdTTL)
    if err != nil { return ..., err }

    if err := s.repo.Reserve(ctx, r); err != nil { return ..., err }

    // Emit events synchronously for now (dispatcher added in step 5.3)
    _ = screening // will be passed to event for price lookup
    return r, nil
}
```

6. Keep `application/booking/service.go` for `GetUserBookings` (query only)

**Verify**: `make test-unit` passes.

---

### Step 5.2 — Create `application/catalog` package (45 min)

Extract from `application/movie/service.go`:

1. Create `backend/internal/application/catalog/`
2. Create `commands.go` with `CreateMovieCommand`, `CreateScreeningCommand`
3. Create `service.go` — same logic, using `catalog.Repository`, `catalog.Screening`
4. Mark `application/movie/` as deprecated (keep temporarily for handler compatibility)

**Verify**: `make test-unit` passes.

---

### Step 5.3 — Add in-process event dispatcher (1h)

**New file**: `backend/internal/infrastructure/events/dispatcher.go`

```go
package events

import (
    "context"
    "fmt"
    "log/slog"
    "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

type Handler func(ctx context.Context, event shared.DomainEvent) error

type Dispatcher struct {
    handlers map[string][]Handler
}

func NewDispatcher() *Dispatcher {
    return &Dispatcher{handlers: make(map[string][]Handler)}
}

func (d *Dispatcher) Register(eventName string, h Handler) {
    d.handlers[eventName] = append(d.handlers[eventName], h)
}

func (d *Dispatcher) Dispatch(ctx context.Context, events []shared.DomainEvent) error {
    for _, evt := range events {
        for _, h := range d.handlers[evt.EventName()] {
            if err := h(ctx, evt); err != nil {
                slog.Error("event handler failed",
                    "event", evt.EventName(), "error", err)
                // continue dispatching other handlers
            }
        }
    }
    return nil
}
```

**New file**: `backend/internal/application/booking/event_handlers.go`

```go
package booking

// ReservationEventHandler reacts to Reservation context events
// and maintains the Booking aggregate's state.
type ReservationEventHandler struct {
    repo        bookingdomain.Repository
    catalogRepo catalogdomain.Repository
    holdTTL     time.Duration
}

func (h *ReservationEventHandler) OnSeatsReserved(ctx context.Context, evt shared.DomainEvent) error {
    e := evt.(reservationdomain.SeatsReserved)
    // fetch screening price (ACL)
    screening, err := h.catalogRepo.FindScreening(ctx, e.ScreeningID)
    if err != nil { return err }
    // build seats
    seats := buildBookedSeats(e.SeatIDs)
    b, err := bookingdomain.New(e.ReservationID.String(), e.UserID, e.ScreeningID,
        screening.MovieID, seats, screening.Price, h.holdTTL)
    if err != nil { return err }
    return h.repo.Save(ctx, b)
}

func (h *ReservationEventHandler) OnReservationConfirmed(ctx context.Context, evt shared.DomainEvent) error {
    e := evt.(reservationdomain.ReservationConfirmed)
    b, err := h.repo.FindByReservationID(ctx, e.ReservationID.String())
    if err != nil { return err }
    if err := b.Confirm(); err != nil { return err }
    return h.repo.Update(ctx, b)
}

func (h *ReservationEventHandler) OnReservationReleased(ctx context.Context, evt shared.DomainEvent) error {
    e := evt.(reservationdomain.ReservationReleased)
    b, err := h.repo.FindByReservationID(ctx, e.ReservationID.String())
    if err != nil { return err }
    _ = b.Cancel()
    return h.repo.Update(ctx, b)
}
```

Wire up in `cmd/api/main.go`:
```go
dispatcher := events.NewDispatcher()
bookingEvtHandler := appbooking.NewReservationEventHandler(bookingRepo, catalogRepo, cfg.Booking.HoldTTL)
dispatcher.Register("SeatsReserved",        bookingEvtHandler.OnSeatsReserved)
dispatcher.Register("ReservationConfirmed", bookingEvtHandler.OnReservationConfirmed)
dispatcher.Register("ReservationReleased",  bookingEvtHandler.OnReservationReleased)
```

Inject `dispatcher` into `application/reservation.Service`.

**Verify**: End-to-end flow (hold → confirm) works. `make test-unit` passes.

---

### Step 5.4 — Add pagination to `GetUserBookings` (30 min)

**File**: `backend/internal/domain/booking/repository.go`:
```go
// Before
FindByUserID(ctx context.Context, userID string) ([]Booking, error)

// After
FindByUserID(ctx context.Context, userID string, p shared.Pagination) ([]Booking, int, error)
// returns (bookings, totalCount, error)
```

**File**: `backend/internal/infrastructure/persistence/mongodb/booking_repository.go`:
```go
func (r *BookingRepository) FindByUserID(ctx context.Context, userID string, p shared.Pagination) ([]Booking, int, error) {
    filter := bson.M{"user_id": userID}
    total, err := coll.CountDocuments(ctx, filter)
    opts := options.Find().SetSort(...).SetSkip(int64(p.Offset())).SetLimit(int64(p.Limit()))
    // ...
}
```

Update handler to read `page` and `page_size` query params.

**Verify**: `GET /users/:id/bookings?page=1&page_size=10` returns paginated results.

---

## Milestone 6 — Infrastructure Improvements

---

### Step 6.1 — Fix `GetSeatStatuses` N+1 Redis problem (2h)

**Current problem** (from concurrency-analysis.md): per held seat, 3 Redis round trips (GET key, TTL, GET session) = O(N) calls.

**New approach** — store userID directly in the seat key value instead of requiring a session lookup:

```
seat:{screeningID}:{seatID}  →  "{sessionID}:{userID}:{status}"
```

Or, better: use a Redis Hash per showtime for O(1) availability query:

```
seatmap:{screeningID}  →  Hash{seatID: "sessionID|userID|status|expiresAt"}
```

**Lua script changes**:

```lua
-- luaHoldSeats update: also update the hash
for i = 1, #KEYS do
    redis.call('SET', KEYS[i], ARGV[1], 'NX', 'EX', tonumber(ARGV[2]))
    -- KEYS[i] is seat key; also update hash field
end
redis.call('HMSET', ARGV[4], ...)  -- ARGV[4] = seatmap hash key
```

Or simpler approach: **pipeline** the existing calls to batch Redis round trips:

```go
// Use redis.Pipeline() to batch GET + TTL per seat
pipe := r.rdb.Pipeline()
for _, key := range seatKeys {
    pipe.Get(ctx, key)
    pipe.TTL(ctx, key)
}
results, _ := pipe.Exec(ctx)
```

This reduces N×3 round trips to 1 pipeline call. Session lookup for `HeldByMe` can be batched with `MGET`.

**Verify**: `make test-integration` passes. Benchmark shows `GetSeatStatuses` completes in < 5ms for 120-seat hall.

---

### Step 6.2 — Add confirmed-seat cleanup (1h)

Confirmed seat keys currently live in Redis forever (no TTL). Add a background cleaner:

**New file**: `backend/internal/infrastructure/persistence/redis/seat_cleanup.go`

```go
package redis

// CleanConfirmedSeats removes seat keys that have no TTL (confirmed)
// for screenings whose EndTime has passed.
// Called by a background goroutine or cron job.
func (r *SeatReservationRepository) CleanConfirmedSeats(ctx context.Context, screeningID string) (int64, error) {
    pattern := fmt.Sprintf(seatKeyFmt, screeningID, "*")
    var deleted int64
    iter := r.rdb.Scan(ctx, 0, pattern, 0).Iterator()
    for iter.Next(ctx) {
        key := iter.Val()
        ttl, _ := r.rdb.TTL(ctx, key).Result()
        if ttl == -1 { // -1 = no TTL = confirmed
            r.rdb.Del(ctx, key)
            deleted++
        }
    }
    return deleted, iter.Err()
}
```

Wire in `main.go` as a background goroutine triggered after `HOLD_TTL` × 2:
```go
go func() {
    ticker := time.NewTicker(cfg.Booking.HoldTTL * 2)
    for range ticker.C {
        // clean confirmed seats for past screenings
    }
}()
```

**Verify**: After confirming a booking, confirmed seats are deleted from Redis after the cleanup window.

---

### Step 6.3 — Add `RequestID` middleware (30 min)

**New file**: `backend/internal/interfaces/http/middleware/request_id.go`

```go
package middleware

import (
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
)

const RequestIDKey = "request_id"

func RequestID() gin.HandlerFunc {
    return func(c *gin.Context) {
        id := c.GetHeader("X-Request-ID")
        if id == "" { id = uuid.New().String() }
        c.Set(RequestIDKey, id)
        c.Header("X-Request-ID", id)
        c.Next()
    }
}
```

**Update** `middleware/logger.go` to include `request_id` field.

**Update** `router.go` to add `middleware.RequestID()` before `middleware.Logger()`.

**Verify**: Every response has `X-Request-ID` header. Log lines include `request_id` field.

---

### Step 6.4 — Add rate limiting middleware (1h)

**New dependency**: `golang.org/x/time/rate` (stdlib-adjacent, no new external dep needed beyond what's already in go.mod)

**New file**: `backend/internal/interfaces/http/middleware/ratelimit.go`

```go
package middleware

import (
    "net/http"
    "sync"
    "time"
    "golang.org/x/time/rate"
    "github.com/gin-gonic/gin"
)

type ipLimiter struct {
    limiter  *rate.Limiter
    lastSeen time.Time
}

// RateLimit creates per-IP rate limiting.
// rps = requests per second, burst = burst size.
func RateLimit(rps float64, burst int) gin.HandlerFunc {
    limiters := make(map[string]*ipLimiter)
    var mu sync.Mutex

    go func() {  // cleanup old entries
        for range time.Tick(time.Minute) {
            mu.Lock()
            for ip, il := range limiters {
                if time.Since(il.lastSeen) > 3*time.Minute { delete(limiters, ip) }
            }
            mu.Unlock()
        }
    }()

    return func(c *gin.Context) {
        ip := c.ClientIP()
        mu.Lock()
        if _, ok := limiters[ip]; !ok {
            limiters[ip] = &ipLimiter{limiter: rate.NewLimiter(rate.Limit(rps), burst)}
        }
        limiters[ip].lastSeen = time.Now()
        ok := limiters[ip].limiter.Allow()
        mu.Unlock()
        if !ok {
            c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
            return
        }
        c.Next()
    }
}
```

Add to router with sensible defaults:
```go
r.Use(middleware.RateLimit(50, 100))  // 50 req/s per IP, burst 100
```

**Verify**: `make test-unit` passes. Rapid requests from same IP return 429 after burst.

---

## Milestone 7 — Interface Layer Cleanup

---

### Step 7.1 — Move JSON tags from domain to DTOs (45 min)

`SeatStatus` (now `SeatAvailability`) has JSON tags in the domain. Remove them.

**`backend/internal/interfaces/http/dto/reservation_dto.go`** — add:
```go
// SeatAvailabilityResponse is the HTTP response DTO (json tags live here only)
type SeatAvailabilityResponse struct {
    SeatID       string `json:"seat_id"`
    Status       string `json:"status"`
    ReservedByMe bool   `json:"reserved_by_me"`
    ExpiresAt    *int64 `json:"expires_at,omitempty"` // unix seconds for client countdown
}

func FromSeatAvailability(a reservationdomain.SeatAvailability) SeatAvailabilityResponse {
    var expiresAt *int64
    if a.ExpiresAt != nil {
        unix := a.ExpiresAt.Unix()
        expiresAt = &unix
    }
    return SeatAvailabilityResponse{
        SeatID:       a.SeatID,
        Status:       string(a.Status),
        ReservedByMe: a.ReservedByMe,
        ExpiresAt:    expiresAt,
    }
}
```

**Verify**: `grep -r "json:\"" ./internal/domain/` returns nothing.

---

### Step 7.2 — Consolidate error → HTTP status mapping (30 min)

**New file**: `backend/internal/interfaces/http/errors.go`

```go
package http

import (
    "errors"
    "net/http"
    reservationdomain "github.com/rabbicse/movie-ticket-booking/internal/domain/reservation"
    bookingdomain     "github.com/rabbicse/movie-ticket-booking/internal/domain/booking"
    catalogdomain     "github.com/rabbicse/movie-ticket-booking/internal/domain/catalog"
)

func httpStatusFor(err error) int {
    switch {
    case errors.Is(err, reservationdomain.ErrSeatAlreadyReserved):   return http.StatusConflict
    case errors.Is(err, reservationdomain.ErrReservationNotFound):   return http.StatusNotFound
    case errors.Is(err, reservationdomain.ErrReservationExpired):    return http.StatusGone
    case errors.Is(err, reservationdomain.ErrUnauthorized):          return http.StatusForbidden
    case errors.Is(err, reservationdomain.ErrMaxSeatsExceeded),
         errors.Is(err, reservationdomain.ErrNoSeatsSelected):       return http.StatusBadRequest
    case errors.Is(err, bookingdomain.ErrBookingNotFound):           return http.StatusNotFound
    case errors.Is(err, catalogdomain.ErrScreeningNotFound),
         errors.Is(err, catalogdomain.ErrMovieNotFound):             return http.StatusNotFound
    default:                                                          return http.StatusInternalServerError
    }
}

type errorBody struct {
    Error string `json:"error"`
    Code  string `json:"code,omitempty"` // machine-readable code for frontend
}
```

Replace all inline `switch` blocks in handlers with calls to `httpStatusFor`.

**Verify**: `make test-unit` passes. Handler tests confirm correct status codes.

---

### Step 7.3 — Rename handler files to match bounded contexts (15 min)

```
handler/booking_handler.go → handler/reservation_handler.go  (hold, confirm, release, seat map)
handler/movie_handler.go   → handler/catalog_handler.go      (list, get movie, get screening)
handler/admin_handler.go   → (unchanged — uses catalog service)
```

Add a `handler/booking_handler.go` for the query side (`GET /users/:id/bookings`).

**Verify**: `go build ./...` passes.

---

### Step 7.4 — Rename API endpoint terms (30 min)

Update URL paths to match the ubiquitous language from Phase 2:

```
Current                                  Target
POST /showtimes/:id/hold              →  POST /screenings/:id/reservations
PUT  /sessions/:id/confirm            →  PUT  /reservations/:id/confirm
DELETE /sessions/:id                  →  DELETE /reservations/:id
GET  /showtimes/:id/seats             →  GET  /screenings/:id/availability
GET  /showtimes/:id                   →  GET  /screenings/:id
```

**Important**: Add the old paths as deprecated aliases for backwards compatibility:
```go
// Deprecated aliases — remove after frontend migration
api.POST("/showtimes/:showtimeId/hold",    reservationH.ReserveSeats)
api.PUT("/sessions/:sessionId/confirm",    reservationH.ConfirmReservation)
api.DELETE("/sessions/:sessionId",         reservationH.CancelReservation)
api.GET("/showtimes/:showtimeId/seats",    reservationH.GetAvailability)
```

**Verify**: Both old and new URL patterns work. Frontend still functions unchanged.

---

## Milestone 8 — Verification

---

### Step 8.1 — Architecture validation checklist (15 min)

Run all assertions from `clean-architecture.md` Section 12:

```bash
# Domain has no external imports
go build ./internal/domain/... ./internal/shared/...

# No framework types in domain
grep -r "gin\|redis\|mongo" ./internal/domain/ ./internal/shared/
# → must return nothing

# No JSON tags in domain
grep -r 'json:"' ./internal/domain/ ./internal/shared/
# → must return nothing

# No infrastructure in application
grep -r "infrastructure" ./internal/application/
# → must return nothing

# No infrastructure in interfaces
grep -r "infrastructure" ./internal/interfaces/
# → must return nothing

go vet ./...
```

**Gate**: All checks must pass before continuing.

---

### Step 8.2 — Full test suite (30 min)

```bash
cd backend
make test-unit        # domain + application + handler unit tests
make test-integration # Redis + MongoDB integration tests with testcontainers
```

**Gate**: 100% pass, zero data races (`-race` flag in Makefile already set).

---

### Step 8.3 — Load test smoke run (15 min)

```bash
make load-test-smoke   # 1 VU, 10s — confirms basic API functionality
make load-test-concurrent  # 500 VUs on same seats — confirms Lua lock still correct
```

**Gate**: `concurrent_hold` test: exactly 1 success, 499 failures (409). Zero unexpected errors.

---

### Step 8.4 — Manual end-to-end flow (10 min)

```bash
make dev-up
cd backend && make run

# Hold seats
curl -X POST http://localhost:8080/api/v1/screenings/dune2-hall1-1/reservations \
  -H "Content-Type: application/json" \
  -d '{"user_id":"user-1","seat_ids":["A1","A2"]}'

# Confirm
curl -X PUT http://localhost:8080/api/v1/reservations/{reservation_id}/confirm \
  -d '{"user_id":"user-1"}'

# Verify booking record
curl http://localhost:8080/api/v1/users/user-1/bookings?page=1&page_size=10
```

**Gate**: Full flow completes with expected responses. No 500 errors.

---

## Rollback Plan

Each milestone is a self-contained batch of commits. If any milestone introduces a regression:

1. `git revert` the commits for that milestone
2. Run `make test-unit` to confirm revert is clean
3. Re-plan the affected steps before retrying

Milestones 1–3 (quick wins + shared kernel + domain hardening) are completely safe to run independently and have no mutual dependencies with M4–M7.

---

## PR Strategy

Suggested PR structure (one PR per milestone, reviewed before next starts):

| PR | Milestone | Risk | Review Focus |
|---|---|---|---|
| PR-01 | M1 Quick Wins | 🟢 Low | Security fixes, no logic change |
| PR-02 | M2 Shared Kernel | 🟢 Low | New files only |
| PR-03 | M3 Domain Hardening | 🟡 Medium | Aggregate behaviour changes |
| PR-04 | M4 Package Restructure | 🟠 High | Import graph, build correctness |
| PR-05 | M5 Application Layer | 🟠 High | Event flow, service orchestration |
| PR-06 | M6 Infrastructure | 🟡 Medium | Redis N+1 fix, cleanup job |
| PR-07 | M7 Interface Layer | 🟡 Medium | DTO mapping, middleware |
| PR-08 | M8 Verification | 🟢 Low | Sign-off only |
