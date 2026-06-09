# Clean Architecture Design

_Phase 4 — Layer definitions, dependency rules, wiring — 2026-06-09_  
_Builds on: ddd-design.md (Phase 3), architecture-review.md (Phase 1)_

---

## 1. The Dependency Rule

> Source code dependencies must point only inward — toward higher-level policy.

```
┌──────────────────────────────────────────────────────────────────────┐
│                                                                      │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │  INFRASTRUCTURE  (outermost — depends on everything)        │   │
│   │                                                             │   │
│   │   ┌─────────────────────────────────────────────────────┐  │   │
│   │   │  INTERFACES  (HTTP handlers, DTOs, middleware)      │  │   │
│   │   │                                                     │  │   │
│   │   │   ┌─────────────────────────────────────────────┐  │  │   │
│   │   │   │  APPLICATION  (use cases, commands, events) │  │  │   │
│   │   │   │                                             │  │  │   │
│   │   │   │   ┌─────────────────────────────────────┐  │  │  │   │
│   │   │   │   │  DOMAIN  (innermost — no deps)       │  │  │  │   │
│   │   │   │   │  entities · VOs · repo interfaces   │  │  │  │   │
│   │   │   │   │  domain events · errors              │  │  │  │   │
│   │   │   │   └─────────────────────────────────────┘  │  │  │   │
│   │   │   └─────────────────────────────────────────────┘  │  │   │
│   │   └─────────────────────────────────────────────────────┘  │   │
│   └─────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

**Arrows of dependency (all point inward):**

```
interfaces/http ──────────────────────────────► application
interfaces/http ──────────────────────────────► domain (errors only)
application ──────────────────────────────────► domain
infrastructure/persistence ───────────────────► domain  (implements interfaces)
infrastructure/events ────────────────────────► shared
cmd/api/main.go ──────────────────────────────► ALL (wiring only)
```

**What never happens:**
```
domain        ✗──► application
domain        ✗──► infrastructure
domain        ✗──► interfaces
application   ✗──► infrastructure  (uses interfaces, never concrete types)
application   ✗──► interfaces/http
```

---

## 2. Layer Definitions

### Layer 1 — Domain

**Location**: `internal/shared/`, `internal/domain/`  
**Allowed imports**: stdlib only (`time`, `fmt`, `errors`, `strings`)  
**Forbidden imports**: anything in `github.com/rabbicse/...` except `internal/shared`

**Contains**:
- Aggregate roots with lifecycle methods
- Value objects (immutable, validated on construction)
- Domain events (structs implementing `shared.DomainEvent`)
- Repository interfaces (Go interfaces — no implementation)
- Domain errors (sentinel `var Err... = errors.New(...)`)
- Domain services (pure functions operating on domain objects — rare)

**Does NOT contain**:
- JSON struct tags → those belong in DTOs (interfaces layer)
- Redis/MongoDB types → those belong in infrastructure
- Logging calls → domain is silent; services log
- HTTP status codes → handler concern
- `uuid` package calls are acceptable inside constructors (pure generation function)

**Test strategy**: Pure unit tests. No mocks, no testcontainers. Just call methods and assert state.

```go
// Example: pure domain test
func TestBooking_ConfirmExpired(t *testing.T) {
    b, _ := booking.New("res-1", userID, "scr-1", "movie-1", seats, price, -1*time.Second)
    err := b.Confirm()
    assert.ErrorIs(t, err, booking.ErrBookingExpired)
}
```

---

### Layer 2 — Application

**Location**: `internal/application/`  
**Allowed imports**: `internal/domain/...`, `internal/shared`, stdlib  
**Forbidden imports**: `gin`, `redis`, `mongo`, any HTTP/DB library

**Contains**:
- Use case services (`catalog.Service`, `reservation.Service`, `booking.Service`)
- Command structs (inputs for write operations)
- Query structs (inputs for read operations)
- Event handlers (react to domain events, update read-side)
- Orchestration only — no business logic

**Does NOT contain**:
- SQL/Redis/MongoDB queries (those are behind repository interfaces)
- HTTP parsing, status codes, JSON encoding
- Business rules (those live in domain aggregates)

**Pattern — thin service**:
```
service method:
  1. validate command fields (not business rules — just "is this non-empty?")
  2. load aggregate(s) via repository interface
  3. call aggregate method (business logic happens here)
  4. persist via repository interface
  5. collect and dispatch domain events
  6. return result
```

**Test strategy**: Unit tests with hand-written mock repositories.

```go
// Example: application-layer test with mock
func TestReservationService_ReserveSeats_SeatTaken(t *testing.T) {
    repo := &mockReservationRepo{reserveErr: reservation.ErrSeatAlreadyReserved}
    svc  := NewService(repo, mockCatalogRepo{}, mockDispatcher{}, 4, 10*time.Minute)
    _, err := svc.ReserveSeats(ctx, ReserveSeatsCommand{...})
    assert.ErrorIs(t, err, reservation.ErrSeatAlreadyReserved)
}
```

---

### Layer 3 — Infrastructure

**Location**: `internal/infrastructure/`  
**Allowed imports**: `internal/domain/...`, `internal/shared`, external libraries (redis, mongo, etc.)  
**Forbidden imports**: `internal/application`, `internal/interfaces`

**Contains**:
- Repository implementations (`redis.SeatReservationRepository`, `mongodb.BookingRepository`)
- External client constructors (`redis.NewClient`, `mongodb.NewClient`)
- BSON/JSON document structs (private, never exported to other layers)
- Lua scripts (Redis atomicity)
- Event dispatcher implementation
- Seeder

**Key invariant**: Infrastructure structs implement domain interfaces. The domain defines the shape; infrastructure provides the body.

```go
// Infrastructure declares conformance:
var _ reservation.Repository = (*SeatReservationRepository)(nil)
var _ booking.Repository     = (*BookingRepository)(nil)
var _ catalog.Repository     = (*CatalogRepository)(nil)
```

**Test strategy**: Integration tests with `testcontainers-go`. Tests exercise real Redis and MongoDB.

---

### Layer 4 — Interfaces (Presentation)

**Location**: `internal/interfaces/http/`  
**Allowed imports**: `internal/application/...`, `internal/domain/...` (errors only), `internal/shared`, `gin`  
**Forbidden imports**: `internal/infrastructure`

**Contains**:
- HTTP handlers (thin: parse → call service → encode response)
- Request/response DTOs (JSON struct tags live here, never in domain)
- Middleware (logger, CORS, rate limiter, request ID)
- Router wiring
- Embedded Swagger spec

**Does NOT contain**:
- Business logic
- Direct database calls
- Domain aggregate manipulation

**Handler pattern**:
```go
func (h *ReservationHandler) ReserveSeats(c *gin.Context) {
    var req dto.ReserveSeatsRequest              // 1. parse
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, errorResponse(err)); return
    }
    cmd := req.ToCommand(c.Param("screeningId")) // 2. map to command
    result, err := h.svc.ReserveSeats(c.Request.Context(), cmd)
    if err != nil {                              // 3. map error → HTTP status
        c.JSON(httpStatusFor(err), errorResponse(err)); return
    }
    c.JSON(201, dto.FromReservation(result))     // 4. map result → DTO
}
```

**Error-to-HTTP mapping lives in the handler** (or a shared `errorResponse` helper), never in the service:

```go
// interfaces/http/errors.go
func httpStatusFor(err error) int {
    switch {
    case errors.Is(err, reservation.ErrSeatAlreadyReserved): return 409
    case errors.Is(err, reservation.ErrReservationNotFound): return 404
    case errors.Is(err, reservation.ErrReservationExpired):  return 410
    case errors.Is(err, reservation.ErrUnauthorized):        return 403
    case errors.Is(err, reservation.ErrMaxSeatsExceeded):    return 400
    case errors.Is(err, catalog.ErrScreeningNotFound):       return 404
    default:                                                  return 500
    }
}
```

**Test strategy**: Handler unit tests using `httptest` and mock application services.

---

## 3. Full Dependency Diagram

```
cmd/api/main.go
    │
    │  constructs (wires everything together)
    │
    ├──────────────────────────── infrastructure ──────────────────────────┐
    │  redis.NewClient()                                                   │
    │  mongodb.NewClient()                                                 │
    │  redis.SeatReservationRepository   ──implements──► reservation.Repo  │
    │  mongodb.BookingRepository         ──implements──► booking.Repo      │
    │  mongodb.CatalogRepository         ──implements──► catalog.Repo      │
    │  events.InProcessDispatcher        ──implements──► events.Dispatcher │
    │                                                                      │
    ├──────────────────────────── application ─────────────────────────────┤
    │  reservation.Service(reservationRepo, catalogRepo, dispatcher, ...)  │
    │  booking.Service(bookingRepo)                                        │
    │  catalog.Service(catalogRepo)                                        │
    │  booking.ReservationEventHandler  ◄── dispatcher.Register(...)      │
    │                                                                      │
    ├──────────────────────────── interfaces/http ─────────────────────────┤
    │  ReservationHandler(reservationSvc)                                  │
    │  BookingHandler(bookingSvc)                                          │
    │  CatalogHandler(catalogSvc)                                          │
    │  AdminHandler(catalogSvc)                                            │
    │  Router(handlers, cfg)                                               │
    │                                                                      │
    └──────────────────────────────────────────────────────────────────────┘

Domain layer (no arrows out):
    domain/catalog      ◄── catalog.Repository (interface)
    domain/reservation  ◄── reservation.Repository (interface)
    domain/booking      ◄── booking.Repository (interface)
    domain/identity     ◄── identity.Repository (interface)
    shared              ◄── Money, UserID, DomainEvent, Pagination
```

---

## 4. Wiring (main.go)

The composition root. This is the only place that knows about all layers simultaneously.

```go
// cmd/api/main.go

func main() {
    cfg := config.MustLoad()

    // ── Infrastructure ────────────────────────────────────────────
    rdb         := must(redis.NewClient(cfg.Redis))
    mongoClient := must(mongodb.NewClient(cfg.MongoDB))
    db          := mongodb.Database(mongoClient, cfg.MongoDB)

    catalogRepo      := mongodb.NewCatalogRepository(db)
    bookingRepo      := mongodb.NewBookingRepository(db)
    reservationRepo  := redis.NewSeatReservationRepository(rdb)

    // ── Event Dispatcher ──────────────────────────────────────────
    dispatcher := events.NewInProcessDispatcher()

    // ── Application Services ──────────────────────────────────────
    catalogSvc     := appcatalog.NewService(catalogRepo)
    bookingSvc     := appbooking.NewService(bookingRepo)
    reservationSvc := appreservation.NewService(
        reservationRepo, catalogRepo, dispatcher,
        cfg.Booking.MaxSeatsPerSession, cfg.Booking.HoldTTL,
    )

    // ── Register Event Handlers ───────────────────────────────────
    bookingHandler := appbooking.NewReservationEventHandler(bookingRepo, catalogRepo, cfg.Booking.HoldTTL)
    dispatcher.Register("SeatsReserved",        bookingHandler.OnSeatsReserved)
    dispatcher.Register("ReservationConfirmed", bookingHandler.OnReservationConfirmed)
    dispatcher.Register("ReservationReleased",  bookingHandler.OnReservationReleased)

    // ── Seed ──────────────────────────────────────────────────────
    seeder.Seed(ctx, catalogRepo)

    // ── HTTP Layer ────────────────────────────────────────────────
    router := httpinterface.NewRouter(
        catalogSvc, reservationSvc, bookingSvc,
        httpinterface.Config{
            AllowedOrigins: cfg.Server.AllowedOrigins,
            MaxSeats:       cfg.Booking.MaxSeatsPerSession,
            AdminUser:      cfg.Admin.User,      // from env — fixes SM-02
            AdminPassword:  cfg.Admin.Password,
        },
    )

    // ── Server ────────────────────────────────────────────────────
    runServer(router, cfg.Server)
}
```

---

## 5. Interface Contracts (Layer Boundaries)

### Application → Domain (via interfaces)

The application layer depends on these interfaces, never on concrete types:

```go
// Passed into services as constructor parameters
reservation.Repository   → interface defined in domain/reservation
booking.Repository       → interface defined in domain/booking
catalog.Repository       → interface defined in domain/catalog
events.Dispatcher        → interface defined in infrastructure/events
```

### Infrastructure → Domain (implements interfaces)

```go
redis.SeatReservationRepository    implements  reservation.Repository
mongodb.BookingRepository          implements  booking.Repository
mongodb.CatalogRepository          implements  catalog.Repository
events.InProcessDispatcher         implements  events.Dispatcher
```

### Interfaces → Application (via concrete service types)

The HTTP layer takes application service structs directly (same module, acceptable):

```go
handler.CatalogHandler      depends on  *appcatalog.Service
handler.ReservationHandler  depends on  *appreservation.Service
handler.BookingHandler      depends on  *appbooking.Service
```

If test-isolation is needed, extract service interfaces in the application layer.

---

## 6. Framework Confinement

Frameworks must not leak into inner layers.

### Gin (HTTP framework)

| Layer | Gin Usage | Verdict |
|---|---|---|
| Domain | None | ✅ |
| Application | None | ✅ |
| Infrastructure | None | ✅ |
| Interfaces/http | `gin.Context`, `gin.HandlerFunc`, `gin.Engine` | ✅ Correct — confined here |

### Redis (`go-redis`)

| Layer | Redis Usage | Verdict |
|---|---|---|
| Domain | None | ✅ |
| Application | None | ✅ |
| Infrastructure/redis | `redis.Client`, Lua scripts | ✅ Correct |
| Interfaces | None | ✅ |

### MongoDB (`mongo-driver`)

| Layer | Mongo Usage | Verdict |
|---|---|---|
| Domain | None | ✅ |
| Application | None | ✅ |
| Infrastructure/mongodb | `mongo.Client`, BSON, `options.*` | ✅ Correct |
| Interfaces | None | ✅ |

### `log/slog`

| Layer | Logging | Verdict |
|---|---|---|
| Domain | **None** — aggregates are silent | ✅ Required |
| Application | Warn-level for non-fatal infra failures | ✅ Acceptable |
| Infrastructure | Connection/operation errors | ✅ Acceptable |
| Interfaces | Request log via middleware | ✅ Correct |

---

## 7. DTO Mapping Strategy

DTOs live in `interfaces/http/dto/`. They are the translation layer between HTTP JSON and domain/application types.

```
HTTP Request JSON
    │
    ▼
dto.ReserveSeatsRequest   (has json:"" tags)
    │  .ToCommand()
    ▼
application.ReserveSeatsCommand   (no json tags)
    │
    ▼
domain.SeatReservation   (no json tags, no framework imports)
    │
    ▼
application.ReserveSeatsCommand result
    │  dto.FromReservation()
    ▼
dto.ReservationResponse   (has json:"" tags)
    │
    ▼
HTTP Response JSON
```

**Rule**: JSON struct tags exist only in `dto/` structs. Domain objects carry no `json:` tags.

**Example DTO pair**:

```go
// interfaces/http/dto/reservation_dto.go

type ReserveSeatsRequest struct {
    UserID  string   `json:"user_id"  binding:"required"`
    SeatIDs []string `json:"seat_ids" binding:"required,min=1,max=4"`
}

func (r ReserveSeatsRequest) ToCommand(screeningID string) appreservation.ReserveSeatsCommand {
    userID, _ := shared.NewUserID(r.UserID) // validation already passed
    return appreservation.ReserveSeatsCommand{
        UserID:      userID,
        ScreeningID: screeningID,
        SeatIDs:     r.SeatIDs,
    }
}

type ReservationResponse struct {
    ReservationID string   `json:"reservation_id"`
    ScreeningID   string   `json:"screening_id"`
    MovieID       string   `json:"movie_id"`
    SeatIDs       []string `json:"seat_ids"`
    Status        string   `json:"status"`
    ExpiresAt     int64    `json:"expires_at"`  // unix for client countdown
}

func FromReservation(r domain.SeatReservation) ReservationResponse {
    return ReservationResponse{
        ReservationID: r.ID.String(),
        ScreeningID:   r.ScreeningID,
        SeatIDs:       r.SeatIDs(),
        Status:        string(r.Status),
        ExpiresAt:     r.ExpiresAt.Unix(),
    }
}
```

---

## 8. Configuration Layer

```go
// internal/config/config.go

type Config struct {
    Server  ServerConfig
    Redis   RedisConfig
    MongoDB MongoDBConfig
    Booking BookingConfig
    Admin   AdminConfig   // NEW: admin credentials from env
}

type AdminConfig struct {
    User     string `env:"ADMIN_USER"     envDefault:"admin"`
    Password string `env:"ADMIN_PASSWORD" envDefault:""` // empty = disabled
}

type RedisConfig struct {
    Addr     string `env:"REDIS_ADDR"     envDefault:"localhost:6379"`  // fixed from 192.168.0.50
    Password string `env:"REDIS_PASSWORD" envDefault:""`
    DB       int    `env:"REDIS_DB"       envDefault:"0"`
}

type MongoDBConfig struct {
    URI      string `env:"MONGODB_URI"      envDefault:"mongodb://localhost:27017"`  // fixed
    Database string `env:"MONGODB_DATABASE" envDefault:"movie_ticket_booking"`
}
```

Config loading must never log sensitive fields (password, full URI with credentials).

---

## 9. Middleware Stack

Order matters. The stack applied to every request:

```
Request
  │
  ▼
1. gin.Recovery()         — catches panics, returns 500
2. middleware.RequestID() — generates/propagates X-Request-ID header
3. middleware.Logger()    — logs after handler, includes request_id field
4. middleware.CORS()      — sets CORS headers; short-circuits OPTIONS
5. middleware.RateLimit() — per-IP token bucket (new)
  │
  ▼
Route handler
```

**`middleware.RequestID()`** — fixes the missing trace correlation:
```go
func RequestID() gin.HandlerFunc {
    return func(c *gin.Context) {
        id := c.GetHeader("X-Request-ID")
        if id == "" { id = uuid.New().String() }
        c.Set("request_id", id)
        c.Header("X-Request-ID", id)
        c.Next()
    }
}
```

**`middleware.Logger()`** — updated to include request_id:
```go
slog.Info("request",
    "request_id", c.GetString("request_id"),
    "method",     c.Request.Method,
    "path",       c.Request.URL.Path,
    "status",     c.Writer.Status(),
    "latency_ms", time.Since(start).Milliseconds(),
    "ip",         c.ClientIP(),
)
```

---

## 10. Testing Strategy Per Layer

### Domain — Pure unit tests

```
backend/internal/domain/reservation/reservation_test.go
backend/internal/domain/booking/booking_test.go
backend/internal/domain/catalog/movie_test.go
backend/internal/shared/money_test.go
```

- No mocks, no interfaces to implement
- Test every invariant, every error path, every state transition
- `go test -race -count=1 ./internal/domain/... ./internal/shared/...`

### Application — Unit tests with mock repos

```
backend/internal/application/reservation/service_test.go
backend/internal/application/booking/event_handlers_test.go
backend/internal/application/catalog/service_test.go
```

- Hand-written mock structs implementing repo interfaces
- Test command validation, event dispatch, cross-context ACL calls
- No Docker required
- `go test -race -count=1 ./internal/application/... -short`

### Infrastructure — Integration tests with real datastores

```
backend/tests/integration/redis_seat_reservation_test.go
backend/tests/integration/mongodb_booking_test.go
backend/tests/integration/mongodb_catalog_test.go
```

- `testcontainers-go` spins real Redis 7 + MongoDB
- Tests `TestConcurrentReservation_ExactlyOneWins` (10k goroutines)
- `go test -race -timeout 120s ./tests/integration/...`

### Interface — Handler tests with mock services

```
backend/internal/interfaces/http/handler/reservation_handler_test.go
backend/internal/interfaces/http/handler/booking_handler_test.go
```

- Use `net/http/httptest`
- Mock application services (hand-written or generated)
- Test: request parsing, error→HTTP status mapping, response encoding
- `go test -race ./internal/interfaces/...`

### Load — k6 scenarios (unchanged)

```
load-tests/booking.js   (smoke, load, spike, concurrent_hold)
```

---

## 11. Current Violations → Target Fixes

| Violation | Current | Target | Layer Affected |
|---|---|---|---|
| JSON tags in domain | `SeatStatus` in `domain/booking` has `json:"..."` | Move to `dto/` as `SeatAvailabilityResponse` | Domain → DTO |
| Redis types in domain | `Session` in `domain/booking` (conceptually Redis) | `SeatReservation` aggregate owns the concept; Redis impl in infra | Domain |
| Business logic in handler | `maxSeats` check in `BookingHandler` | Service only | Interface → Application |
| Hardcoded credentials | `gin.Accounts{"admin":"admin"}` in router | `AdminConfig` from env | Interface → Config |
| Hardcoded IPs in defaults | `192.168.0.50` in config | `localhost` | Config |
| Fire-and-forget persistence | `slog.Warn` on MongoDB save failure | Return error; compensating release | Application |
| No request ID | Logger has no correlation field | `RequestID` middleware | Interface |
| No pagination | `FindByUserID` returns all | `shared.Pagination` in repo interface | Domain → Infra |
| Panic in domain | `Money.Add` panics | Returns `(Money, error)` | Domain |
| Admin bypass domain invariant | `CreateShowtime` skips `AddShowtime` | `CreateScreening` calls `AddScreening` | Application |

---

## 12. Architecture Validation Checklist

Before merging any refactoring PR, verify:

- [ ] `go build ./internal/domain/...` passes with zero imports of non-stdlib packages
- [ ] `grep -r "gin\|redis\|mongo" ./internal/domain/` returns nothing
- [ ] `grep -r "json:\"" ./internal/domain/` returns nothing (no JSON tags)
- [ ] `grep -r "infrastructure" ./internal/application/` returns nothing
- [ ] `grep -r "infrastructure" ./internal/interfaces/` returns nothing
- [ ] `go vet ./...` passes
- [ ] `go test -race ./internal/domain/...` passes (pure unit tests)
- [ ] `go test -race ./internal/application/...` passes (mock tests)
- [ ] `go test -race ./tests/integration/...` passes (real datastores)
