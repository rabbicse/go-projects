# Testing Strategy

_Phase 12 — Test pyramid, patterns, coverage targets — 2026-06-09_  
_Builds on: clean-architecture.md (Phase 4), concurrency-review.md (Phase 6), backend-refactor-plan.md (Phase 5)_

---

## 1. Testing Philosophy

Tests in this codebase serve three distinct purposes:

1. **Correctness proofs** — domain invariants and business rules that must never regress.  
2. **Integration contracts** — the infrastructure implementations (Redis Lua, MongoDB queries) behave as specified.  
3. **Concurrency guarantees** — the atomic seat-locking properties hold under real contention.

The testing pyramid reflects this:

```
            ▲
           /|\
          / | \          Load Tests (k6)
         /  |  \         — 4 scenarios, manual trigger
        /   |   \        — performance SLOs, conflict behaviour
       ─────────────
      /     |     \      Integration Tests (testcontainers)
     /      |      \     — Redis + MongoDB with real containers
    /       |       \    — 1 test = 1 container lifecycle
   ─────────────────────
  /         |         \  Unit Tests (pure Go, no I/O)
 /          |          \ — Domain layer: 100% target
/           |           \— Application layer: 90% target
─────────────────────────— Handler layer: 80% target
```

**What to test at each layer**:

| Layer | Test type | Dependencies | Speed |
|---|---|---|---|
| `domain/` | Unit | None | <1ms/test |
| `application/` | Unit | Hand-rolled mocks | <5ms/test |
| `interfaces/http/` | Unit | Mock services, httptest | <10ms/test |
| `infrastructure/` | Integration | testcontainers (real Redis + MongoDB) | ~5s startup |
| End-to-end | Integration | Full stack via docker-compose | ~15s startup |
| Load | k6 | Running backend + Redis + MongoDB | Minutes |

---

## 2. Current Test Inventory

### Existing

| Test | Location | Type | Status |
|---|---|---|---|
| `TestConcurrentHold_ExactlyOneWins` | `tests/integration/redis_seat_lock_test.go` | Concurrency | ✅ Works |

### Missing (by layer)

**Domain** — zero tests currently:
- `TestBooking_*` — aggregate state machine
- `TestMovie_AddShowtime_*` — overlap invariant
- `TestMoney_*` — value object arithmetic and error handling

**Application** — zero tests currently:
- `TestBookingService_*` — 6 core scenarios
- `TestMovieService_*` — 4 scenarios

**Handlers** — zero tests currently:
- `TestBookingHandler_*` — 8 HTTP scenarios
- `TestMovieHandler_*` — 4 HTTP scenarios

**Infrastructure** — 1 test, 9+ missing:
- Seat lock: confirm, release, pipeline correctness
- Booking repository: CRUD, cursor pagination
- Movie/Screening repository: overlap detection

**Concurrency** — 7 missing (identified in Phase 6):
- RC-01 confirm + release race
- RC-02 TTL boundary race
- RC-03 cleanup deletes active keys
- Concurrent confirm idempotency
- Pipeline result correctness
- Compensation fires on MongoDB failure
- Rate limiter under concurrent requests

**Frontend** — zero tests currently (Phase 8 scope):
- `useBookingFlow` state machine transitions
- `useSeatAvailability` hook
- `SeatGrid` rendering

---

## 3. Domain Unit Tests

Domain tests are pure — no mocks, no I/O, no goroutines. They are the fastest and highest-value tests in the codebase.

### `internal/domain/booking/booking_test.go`

```go
package booking_test

import (
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "your/module/internal/domain/booking"
    "your/module/internal/domain/shared"
)

// ── Builders ─────────────────────────────────────────────────────────────────

func aBooking(opts ...func(*booking.Booking)) *booking.Booking {
    b := booking.New(
        booking.BookingID("bkg_test"),
        "screening_1",
        "user_1",
        []string{"A1", "A2"},
        shared.MustMoney(2400, "USD"),
    )
    for _, opt := range opts { opt(b) }
    return b
}

func withStatus(status booking.Status) func(*booking.Booking) {
    return func(b *booking.Booking) { /* use exported method or test helper */ }
}

// ── Booking Aggregate ─────────────────────────────────────────────────────────

func TestBooking_New_SelfAssignsID(t *testing.T) {
    b := aBooking()
    assert.NotEmpty(t, b.ID())
    assert.Equal(t, booking.StatusHeld, b.Status())
}

func TestBooking_New_PopulatesFields(t *testing.T) {
    b := aBooking()
    assert.Equal(t, "screening_1", b.ScreeningID())
    assert.Equal(t, "user_1", b.UserID())
    assert.Equal(t, []string{"A1", "A2"}, b.SeatIDs())
    assert.Equal(t, int64(2400), b.Total().Cents())
    assert.Equal(t, "USD", b.Total().Currency())
}

func TestBooking_Confirm_TransitionsToConfirmed(t *testing.T) {
    b := aBooking()
    err := b.Confirm()
    require.NoError(t, err)
    assert.Equal(t, booking.StatusConfirmed, b.Status())
    assert.NotNil(t, b.ConfirmedAt())
}

func TestBooking_Confirm_AlreadyConfirmed_ReturnsError(t *testing.T) {
    b := aBooking()
    _ = b.Confirm()
    err := b.Confirm()
    assert.ErrorIs(t, err, booking.ErrAlreadyConfirmed)
}

func TestBooking_Confirm_Released_ReturnsError(t *testing.T) {
    b := aBooking()
    _ = b.Release()
    err := b.Confirm()
    assert.ErrorIs(t, err, booking.ErrInvalidTransition)
}

func TestBooking_Release_TransitionsToReleased(t *testing.T) {
    b := aBooking()
    err := b.Release()
    require.NoError(t, err)
    assert.Equal(t, booking.StatusReleased, b.Status())
    assert.NotNil(t, b.ReleasedAt())
}

func TestBooking_Release_AlreadyConfirmed_ReturnsError(t *testing.T) {
    b := aBooking()
    _ = b.Confirm()
    err := b.Release()
    assert.ErrorIs(t, err, booking.ErrAlreadyConfirmed)
}

func TestBooking_Confirm_EmitsDomainEvent(t *testing.T) {
    b := aBooking()
    _ = b.Confirm()
    events := b.PopEvents()
    require.Len(t, events, 1)
    _, ok := events[0].(booking.BookingConfirmedEvent)
    assert.True(t, ok, "expected BookingConfirmedEvent, got %T", events[0])
}

func TestBooking_PopEvents_ClearsEvents(t *testing.T) {
    b := aBooking()
    _ = b.Confirm()
    b.PopEvents()              // first call: returns events
    events := b.PopEvents()   // second call: empty
    assert.Empty(t, events)
}
```

### `internal/domain/movie/movie_test.go`

```go
package movie_test

func TestMovie_AddShowtime_Success(t *testing.T) {
    m := movieBuilder().Build()
    err := m.AddScreening(screeningAt("Screen 1", 10, 12))
    require.NoError(t, err)
    assert.Len(t, m.Screenings(), 1)
}

func TestMovie_AddShowtime_Overlap_SameScreen_Rejected(t *testing.T) {
    m := movieBuilder().Build()
    s1 := screeningAt("Screen 1", 18, 20)   // 18:00–20:00
    s2 := screeningAt("Screen 1", 19, 21)   // 19:00–21:00 — overlaps

    require.NoError(t, m.AddScreening(s1))
    err := m.AddScreening(s2)
    assert.ErrorIs(t, err, movie.ErrScreeningOverlap)
}

func TestMovie_AddShowtime_SameTime_DifferentScreen_Allowed(t *testing.T) {
    m := movieBuilder().Build()
    s1 := screeningAt("Screen 1", 18, 20)
    s2 := screeningAt("Screen 2", 18, 20)  // same time, different screen

    require.NoError(t, m.AddScreening(s1))
    require.NoError(t, m.AddScreening(s2))
}

func TestMovie_AddShowtime_AdjacentSlots_Allowed(t *testing.T) {
    m := movieBuilder().Build()
    s1 := screeningAt("Screen 1", 18, 20)  // ends 20:00
    s2 := screeningAt("Screen 1", 20, 22)  // starts 20:00 — adjacent, not overlapping

    require.NoError(t, m.AddScreening(s1))
    require.NoError(t, m.AddScreening(s2))
}
```

### `internal/domain/shared/money_test.go`

```go
package shared_test

func TestMoney_Add_SameCurrency(t *testing.T) {
    a := shared.MustMoney(1200, "USD")
    b := shared.MustMoney(800, "USD")
    result, err := a.Add(b)
    require.NoError(t, err)
    assert.Equal(t, int64(2000), result.Cents())
    assert.Equal(t, "USD", result.Currency())
}

func TestMoney_Add_CurrencyMismatch_ReturnsError(t *testing.T) {
    a := shared.MustMoney(1200, "USD")
    b := shared.MustMoney(800, "EUR")
    _, err := a.Add(b)
    // MUST return error, not panic — fixes current bug where Money.Add() panics
    assert.ErrorIs(t, err, shared.ErrCurrencyMismatch)
}

func TestMoney_IsZero(t *testing.T) {
    assert.True(t, shared.MustMoney(0, "USD").IsZero())
    assert.False(t, shared.MustMoney(1, "USD").IsZero())
}

func TestMoney_Negative_Rejected(t *testing.T) {
    _, err := shared.NewMoney(-1, "USD")
    assert.ErrorIs(t, err, shared.ErrNegativeAmount)
}
```

---

## 4. Application Layer Unit Tests

Application tests use hand-rolled mocks. No generated mocks — they introduce a build dependency and obscure what the interface contract actually is.

### Mock Pattern

```go
// application/booking/service_test.go

type mockSeatLockRepo struct {
    mock.Mock
}

func (m *mockSeatLockRepo) HoldSeats(ctx context.Context, screeningID string, seatIDs []string, ttl time.Duration) (*domain.SeatReservation, error) {
    args := m.Called(ctx, screeningID, seatIDs, ttl)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*domain.SeatReservation), args.Error(1)
}

func (m *mockSeatLockRepo) ConfirmSeats(ctx context.Context, screeningID string, reservationID string) error {
    return m.Called(ctx, screeningID, reservationID).Error(0)
}

func (m *mockSeatLockRepo) ReleaseSeats(ctx context.Context, screeningID string, reservationID string) error {
    return m.Called(ctx, screeningID, reservationID).Error(0)
}

func (m *mockSeatLockRepo) GetSeatStatuses(ctx context.Context, screeningID, userID string, seatIDs []string) (map[string]domain.SeatStatus, error) {
    args := m.Called(ctx, screeningID, userID, seatIDs)
    return args.Get(0).(map[string]domain.SeatStatus), args.Error(1)
}

type mockBookingRepo struct {
    mock.Mock
}

func (m *mockBookingRepo) Create(ctx context.Context, b *domain.Booking) error {
    return m.Called(ctx, b).Error(0)
}

func (m *mockBookingRepo) Update(ctx context.Context, b *domain.Booking) error {
    return m.Called(ctx, b).Error(0)
}

func (m *mockBookingRepo) FindByReservationID(ctx context.Context, reservationID string) (*domain.Booking, error) {
    args := m.Called(ctx, reservationID)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*domain.Booking), args.Error(1)
}
```

### Service Test Cases

```go
func TestBookingService_ReserveSeats_Success(t *testing.T) {
    lockRepo := new(mockSeatLockRepo)
    bookingRepo := new(mockBookingRepo)
    svc := booking.NewService(lockRepo, bookingRepo, testMetrics(), testLogger())

    reservation := &domain.SeatReservation{
        ID: "res_abc", ScreeningID: "scr_1", SeatIDs: []string{"A1"},
    }
    lockRepo.On("HoldSeats", mock.Anything, "scr_1", []string{"A1"}, mock.Anything).
        Return(reservation, nil)
    bookingRepo.On("Create", mock.Anything, mock.MatchedBy(func(b *domain.Booking) bool {
        return b.Status() == domain.StatusHeld && b.ScreeningID() == "scr_1"
    })).Return(nil)

    res, err := svc.ReserveSeats(context.Background(), booking.ReserveSeatsCommand{
        ScreeningID: "scr_1", UserID: "user_1", SeatIDs: []string{"A1"},
    })
    require.NoError(t, err)
    assert.Equal(t, "res_abc", res.ID)
    lockRepo.AssertExpectations(t)
    bookingRepo.AssertExpectations(t)
}

func TestBookingService_ReserveSeats_SeatsUnavailable_Returns409(t *testing.T) {
    lockRepo := new(mockSeatLockRepo)
    bookingRepo := new(mockBookingRepo)
    svc := booking.NewService(lockRepo, bookingRepo, testMetrics(), testLogger())

    lockRepo.On("HoldSeats", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
        Return(nil, domain.ErrSeatsUnavailable)

    _, err := svc.ReserveSeats(context.Background(), booking.ReserveSeatsCommand{
        ScreeningID: "scr_1", UserID: "user_1", SeatIDs: []string{"A1"},
    })
    assert.ErrorIs(t, err, domain.ErrSeatsUnavailable)
    // MongoDB Create must NOT be called when Redis lock fails
    bookingRepo.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
}

func TestBookingService_ReserveSeats_MongoFails_CompensatesRedis(t *testing.T) {
    // Critical test: if MongoDB write fails after Redis hold, seats must be released
    lockRepo := new(mockSeatLockRepo)
    bookingRepo := new(mockBookingRepo)
    svc := booking.NewService(lockRepo, bookingRepo, testMetrics(), testLogger())

    reservation := &domain.SeatReservation{ID: "res_abc", SeatIDs: []string{"A1"}}
    lockRepo.On("HoldSeats", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
        Return(reservation, nil)
    bookingRepo.On("Create", mock.Anything, mock.Anything).
        Return(errors.New("mongodb: connection refused"))
    lockRepo.On("ReleaseSeats", mock.Anything, mock.Anything, "res_abc").
        Return(nil) // compensation

    _, err := svc.ReserveSeats(context.Background(), booking.ReserveSeatsCommand{
        ScreeningID: "scr_1", UserID: "user_1", SeatIDs: []string{"A1"},
    })
    require.Error(t, err)
    // Compensation must have fired
    lockRepo.AssertCalled(t, "ReleaseSeats", mock.Anything, mock.Anything, "res_abc")
}

func TestBookingService_ConfirmReservation_Success(t *testing.T) {
    // ... similar structure
}

func TestBookingService_ConfirmReservation_Expired_Returns404(t *testing.T) {
    lockRepo := new(mockSeatLockRepo)
    bookingRepo := new(mockBookingRepo)
    svc := booking.NewService(lockRepo, bookingRepo, testMetrics(), testLogger())

    lockRepo.On("ConfirmSeats", mock.Anything, mock.Anything, "res_expired").
        Return(domain.ErrReservationNotFound)

    _, err := svc.ConfirmReservation(context.Background(), booking.ConfirmCommand{
        ReservationID: "res_expired", UserID: "user_1",
    })
    assert.ErrorIs(t, err, domain.ErrReservationNotFound)
}
```

---

## 5. HTTP Handler Tests

Handler tests use `httptest.NewRecorder` and `httptest.NewServer`. They test HTTP contract: status codes, response shapes, correct error codes.

```go
// interfaces/http/handler/booking_handler_test.go
package handler_test

type mockBookingService struct { mock.Mock }

func (m *mockBookingService) ReserveSeats(ctx context.Context, cmd booking.ReserveSeatsCommand) (*domain.SeatReservation, error) {
    args := m.Called(ctx, cmd)
    if args.Get(0) == nil { return nil, args.Error(1) }
    return args.Get(0).(*domain.SeatReservation), args.Error(1)
}
// ... other interface methods

func setupRouter(svc *mockBookingService) *gin.Engine {
    gin.SetMode(gin.TestMode)
    r := gin.New()
    h := handler.NewBookingHandler(svc, 4)
    r.POST("/api/v1/screenings/:screeningId/reservations", h.ReserveSeats)
    r.PUT("/api/v1/reservations/:reservationId/confirm", h.ConfirmReservation)
    r.DELETE("/api/v1/reservations/:reservationId", h.ReleaseReservation)
    return r
}

func TestBookingHandler_Reserve_Success_Returns201(t *testing.T) {
    svc := new(mockBookingService)
    r := setupRouter(svc)

    reservation := &domain.SeatReservation{
        ID: "res_abc", ScreeningID: "scr_1",
        SeatIDs: []string{"A1", "A2"},
        ExpiresAt: time.Now().Add(10 * time.Minute),
    }
    svc.On("ReserveSeats", mock.Anything, booking.ReserveSeatsCommand{
        ScreeningID: "scr_1", UserID: "user_1", SeatIDs: []string{"A1", "A2"},
    }).Return(reservation, nil)

    body := `{"user_id":"user_1","seat_ids":["A1","A2"]}`
    w := httptest.NewRecorder()
    req := httptest.NewRequest("POST", "/api/v1/screenings/scr_1/reservations",
        strings.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    r.ServeHTTP(w, req)

    assert.Equal(t, http.StatusCreated, w.Code)
    var resp map[string]interface{}
    require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
    data := resp["data"].(map[string]interface{})
    assert.Equal(t, "res_abc", data["reservation_id"])
}

func TestBookingHandler_Reserve_SeatsUnavailable_Returns409(t *testing.T) {
    svc := new(mockBookingService)
    r := setupRouter(svc)
    svc.On("ReserveSeats", mock.Anything, mock.Anything).
        Return(nil, domain.ErrSeatsUnavailable)

    body := `{"user_id":"user_1","seat_ids":["A1"]}`
    w := httptest.NewRecorder()
    req := httptest.NewRequest("POST", "/api/v1/screenings/scr_1/reservations",
        strings.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    r.ServeHTTP(w, req)

    assert.Equal(t, http.StatusConflict, w.Code)
    var resp map[string]interface{}
    require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
    errObj := resp["error"].(map[string]interface{})
    assert.Equal(t, "SEATS_UNAVAILABLE", errObj["code"])
}

func TestBookingHandler_Reserve_TooManySeats_Returns422(t *testing.T) {
    svc := new(mockBookingService)
    r := setupRouter(svc)
    // 5 seats — max is 4
    body := `{"user_id":"user_1","seat_ids":["A1","A2","A3","A4","A5"]}`
    w := httptest.NewRecorder()
    req := httptest.NewRequest("POST", "/api/v1/screenings/scr_1/reservations",
        strings.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    r.ServeHTTP(w, req)

    assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
    // Service must NOT be called
    svc.AssertNotCalled(t, "ReserveSeats", mock.Anything, mock.Anything)
}

func TestBookingHandler_Reserve_EmptyBody_Returns400(t *testing.T) {
    svc := new(mockBookingService)
    r := setupRouter(svc)
    w := httptest.NewRecorder()
    req := httptest.NewRequest("POST", "/api/v1/screenings/scr_1/reservations",
        strings.NewReader("not json"))
    req.Header.Set("Content-Type", "application/json")
    r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBookingHandler_Release_Idempotent_Returns204(t *testing.T) {
    svc := new(mockBookingService)
    r := setupRouter(svc)
    svc.On("ReleaseReservation", mock.Anything, mock.Anything).Return(nil)

    w := httptest.NewRecorder()
    req := httptest.NewRequest("DELETE", "/api/v1/reservations/res_abc",
        strings.NewReader(`{"user_id":"user_1"}`))
    r.ServeHTTP(w, req)
    assert.Equal(t, http.StatusNoContent, w.Code)
}
```

---

## 6. Integration Tests

Integration tests require Docker. They use `testcontainers-go` to spin up real Redis 7 and MongoDB instances per test suite.

### Container Setup Pattern

```go
// tests/integration/helpers_test.go
package integration_test

import (
    "context"
    "testing"

    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/modules/mongodb"
    "github.com/testcontainers/testcontainers-go/modules/redis"
)

type testContainers struct {
    redis   *redis.RedisContainer
    mongodb *mongodb.MongoDBContainer
}

func startContainers(t *testing.T) testContainers {
    t.Helper()
    ctx := context.Background()

    redisC, err := redis.RunContainer(ctx,
        testcontainers.WithImage("redis:7-alpine"),
    )
    require.NoError(t, err)
    t.Cleanup(func() { _ = redisC.Terminate(ctx) })

    mongoC, err := mongodb.RunContainer(ctx,
        testcontainers.WithImage("mongo:7"),
    )
    require.NoError(t, err)
    t.Cleanup(func() { _ = mongoC.Terminate(ctx) })

    return testContainers{redis: redisC, mongodb: mongoC}
}

func redisClient(t *testing.T, c *redis.RedisContainer) *redis.Client {
    t.Helper()
    addr, err := c.ConnectionString(context.Background())
    require.NoError(t, err)
    return redis.NewClient(&redis.Options{Addr: strings.TrimPrefix(addr, "redis://")})
}
```

### Redis Integration Tests

```go
// tests/integration/seat_lock_test.go
package integration_test

func TestSeatLockRepository_HoldSeats_Success(t *testing.T) {
    containers := startContainers(t)
    repo := newSeatLockRepo(t, containers.redis)

    res, err := repo.HoldSeats(context.Background(), "scr_1", []string{"A1", "A2"}, 10*time.Minute)
    require.NoError(t, err)
    assert.NotEmpty(t, res.ID)
    assert.Equal(t, []string{"A1", "A2"}, res.SeatIDs)

    // Verify keys exist in Redis with TTL
    client := redisClient(t, containers.redis)
    for _, seatID := range []string{"A1", "A2"} {
        key := fmt.Sprintf("seat:scr_1:%s", seatID)
        ttl := client.TTL(context.Background(), key).Val()
        assert.Greater(t, ttl, 9*time.Minute, "seat %s should have TTL near 10m", seatID)
    }
}

func TestSeatLockRepository_HoldSeats_PartialConflict_RollsBack(t *testing.T) {
    // Pre-lock A2 by another reservation
    containers := startContainers(t)
    repo := newSeatLockRepo(t, containers.redis)
    client := redisClient(t, containers.redis)
    client.Set(context.Background(), "seat:scr_1:A2", "res_other", 10*time.Minute)

    // Attempt to hold A1 and A2 together
    _, err := repo.HoldSeats(context.Background(), "scr_1", []string{"A1", "A2"}, 10*time.Minute)
    require.ErrorIs(t, err, domain.ErrSeatsUnavailable)

    // A1 must NOT be locked (rolled back by Lua script)
    val := client.Get(context.Background(), "seat:scr_1:A1").Val()
    assert.Empty(t, val, "A1 should have been rolled back")
}

func TestSeatLockRepository_Confirm_RemovesTTL(t *testing.T) {
    containers := startContainers(t)
    repo := newSeatLockRepo(t, containers.redis)
    client := redisClient(t, containers.redis)

    res, _ := repo.HoldSeats(context.Background(), "scr_1", []string{"A1"}, 10*time.Minute)
    err := repo.ConfirmSeats(context.Background(), "scr_1", res.ID)
    require.NoError(t, err)

    // TTL should be -1 (no expiry = confirmed)
    ttl := client.TTL(context.Background(), "seat:scr_1:A1").Val()
    assert.Equal(t, time.Duration(-1), ttl, "confirmed seat must have no TTL")
}

func TestSeatLockRepository_Release_DeletesKeys(t *testing.T) {
    containers := startContainers(t)
    repo := newSeatLockRepo(t, containers.redis)
    client := redisClient(t, containers.redis)

    res, _ := repo.HoldSeats(context.Background(), "scr_1", []string{"A1"}, 10*time.Minute)
    err := repo.ReleaseSeats(context.Background(), "scr_1", res.ID)
    require.NoError(t, err)

    exists := client.Exists(context.Background(), "seat:scr_1:A1").Val()
    assert.Equal(t, int64(0), exists)
}

func TestSeatLockRepository_GetSeatStatuses_Pipeline(t *testing.T) {
    containers := startContainers(t)
    repo := newSeatLockRepo(t, containers.redis)
    client := redisClient(t, containers.redis)

    // Set up: A1=held by user2, A2=confirmed, A3=available
    client.Set(context.Background(), "seat:scr_1:A1", "res_other", 10*time.Minute)
    client.Set(context.Background(), "seat:scr_1:A2", "res_confirmed", 0) // no TTL = confirmed
    // A3 not set = available

    allSeats := []string{"A1", "A2", "A3"}
    statuses, err := repo.GetSeatStatuses(context.Background(), "scr_1", "user_1", allSeats)
    require.NoError(t, err)

    assert.Equal(t, domain.SeatStatusHeld,      statuses["A1"])
    assert.Equal(t, domain.SeatStatusConfirmed,  statuses["A2"])
    assert.Equal(t, domain.SeatStatusAvailable,  statuses["A3"])
}
```

### MongoDB Integration Tests

```go
// tests/integration/booking_repository_test.go
func TestBookingRepository_Create_And_FindByReservationID(t *testing.T) {
    containers := startContainers(t)
    repo := newBookingRepo(t, containers.mongodb)

    b := domain.NewBooking("scr_1", "user_1", []string{"A1"}, shared.MustMoney(1200, "USD"))
    b.SetReservationID("res_abc") // set before persisting

    err := repo.Create(context.Background(), b)
    require.NoError(t, err)

    found, err := repo.FindByReservationID(context.Background(), "res_abc")
    require.NoError(t, err)
    assert.Equal(t, b.ID(), found.ID())
    assert.Equal(t, domain.StatusHeld, found.Status())
}

func TestBookingRepository_FindByUserID_CursorPagination(t *testing.T) {
    containers := startContainers(t)
    repo := newBookingRepo(t, containers.mongodb)

    // Create 5 confirmed bookings
    for i := 0; i < 5; i++ {
        b := newConfirmedBooking(fmt.Sprintf("user_1"), fmt.Sprintf("scr_%d", i))
        require.NoError(t, repo.Create(context.Background(), b))
    }

    // Page 1: 3 results
    page1, err := repo.FindByUserID(context.Background(), "user_1", "", 3)
    require.NoError(t, err)
    assert.Len(t, page1.Bookings, 3)
    assert.True(t, page1.HasMore)

    // Page 2: remaining 2 results using cursor
    page2, err := repo.FindByUserID(context.Background(), "user_1", page1.NextCursor, 3)
    require.NoError(t, err)
    assert.Len(t, page2.Bookings, 2)
    assert.False(t, page2.HasMore)
}

func TestScreeningRepository_OverlapDetection(t *testing.T) {
    containers := startContainers(t)
    repo := newScreeningRepo(t, containers.mongodb)

    s1 := newScreening("Screen 1", hour(18), hour(20))
    require.NoError(t, repo.Create(context.Background(), s1))

    // Overlapping screening
    s2 := newScreening("Screen 1", hour(19), hour(21))
    conflicts, err := repo.FindOverlapping(context.Background(), "Screen 1", s2.StartTime, s2.EndTime)
    require.NoError(t, err)
    assert.NotEmpty(t, conflicts, "should find overlapping screening")

    // Non-overlapping (different screen)
    s3 := newScreening("Screen 2", hour(19), hour(21))
    noConflicts, err := repo.FindOverlapping(context.Background(), "Screen 2", s3.StartTime, s3.EndTime)
    require.NoError(t, err)
    assert.Empty(t, noConflicts)
}
```

---

## 7. Concurrency Tests

These tests validate the three race conditions identified in Phase 6. They require real Redis (testcontainers).

```go
// tests/integration/concurrency_test.go

// RC-01: Confirm + release race — release must not win after confirm
func TestConcurrency_ConfirmAndRelease_ConfirmWins(t *testing.T) {
    if testing.Short() { t.Skip("concurrency test") }
    containers := startContainers(t)
    repo := newSeatLockRepo(t, containers.redis)

    res, _ := repo.HoldSeats(context.Background(), "scr_1", []string{"A1"}, 10*time.Minute)

    var confirmErr, releaseErr error
    var wg sync.WaitGroup
    wg.Add(2)

    go func() {
        defer wg.Done()
        confirmErr = repo.ConfirmSeats(context.Background(), "scr_1", res.ID)
    }()
    go func() {
        defer wg.Done()
        releaseErr = repo.ReleaseSeats(context.Background(), "scr_1", res.ID)
    }()
    wg.Wait()

    client := redisClient(t, containers.redis)
    ttl := client.TTL(context.Background(), "seat:scr_1:A1").Val()

    // Exactly one outcome must win
    if confirmErr == nil {
        // Confirm won: seat must be persistent (TTL = -1)
        assert.Equal(t, time.Duration(-1), ttl,
            "if confirm won, seat must have no TTL")
        assert.ErrorIs(t, releaseErr, domain.ErrAlreadyConfirmed,
            "release after confirm must return ErrAlreadyConfirmed")
    } else if releaseErr == nil {
        // Release won: seat key must be gone
        exists := client.Exists(context.Background(), "seat:scr_1:A1").Val()
        assert.Equal(t, int64(0), exists)
    } else {
        t.Fatal("both confirm and release failed — unexpected")
    }
}

// RC-02: TTL expires between checkout page load and confirm click
func TestConcurrency_TTLExpiresBeforeConfirm_Returns404(t *testing.T) {
    containers := startContainers(t)
    repo := newSeatLockRepo(t, containers.redis)

    // Hold with very short TTL (1s)
    res, err := repo.HoldSeats(context.Background(), "scr_1", []string{"A1"}, 1*time.Second)
    require.NoError(t, err)

    // Wait for TTL to expire
    time.Sleep(1100 * time.Millisecond)

    // Confirm must fail — reservation no longer exists
    err = repo.ConfirmSeats(context.Background(), "scr_1", res.ID)
    assert.ErrorIs(t, err, domain.ErrReservationNotFound,
        "confirming expired reservation must return ErrReservationNotFound")

    // Seat must still be available (not stuck)
    statuses, _ := repo.GetSeatStatuses(context.Background(), "scr_1", "user_2", []string{"A1"})
    assert.Equal(t, domain.SeatStatusAvailable, statuses["A1"])
}

// RC-03: Cleanup job must not delete active screening seats
func TestConcurrency_CleanupIgnoresActiveScreening(t *testing.T) {
    containers := startContainers(t)
    repo := newSeatLockRepo(t, containers.redis)

    future := time.Now().Add(1 * time.Hour)
    _, err := repo.HoldSeats(context.Background(), "scr_active", []string{"A1"}, 10*time.Minute)
    require.NoError(t, err)

    // Cleanup with future end time must NOT delete keys
    err = repo.CleanupExpiredScreening(context.Background(), "scr_active", future)
    require.NoError(t, err)

    client := redisClient(t, containers.redis)
    exists := client.Exists(context.Background(), "seat:scr_active:A1").Val()
    assert.Equal(t, int64(1), exists, "active screening seats must not be deleted")
}

// Compensation: MongoDB failure after Redis hold releases the lock
func TestConcurrency_MongoFailure_ReleasesRedisLock(t *testing.T) {
    if testing.Short() { t.Skip() }
    containers := startContainers(t)
    lockRepo := newSeatLockRepo(t, containers.redis)

    // Use a broken booking repo that always returns an error
    bookingRepo := &alwaysFailBookingRepo{}
    svc := booking.NewService(lockRepo, bookingRepo, testMetrics(), testLogger())

    _, err := svc.ReserveSeats(context.Background(), booking.ReserveSeatsCommand{
        ScreeningID: "scr_1", UserID: "user_1", SeatIDs: []string{"A1"},
    })
    require.Error(t, err)

    // The seat must be available again after compensation
    statuses, _ := lockRepo.GetSeatStatuses(context.Background(), "scr_1", "user_1", []string{"A1"})
    assert.Equal(t, domain.SeatStatusAvailable, statuses["A1"],
        "seat must be released after MongoDB failure + compensation")
}

// Existing test — documents the atomic guarantee
func TestConcurrentHold_ExactlyOneWins(t *testing.T) {
    if testing.Short() { t.Skip("long-running concurrency test") }
    // ... existing implementation with 10,000 goroutines
}
```

---

## 8. Load Tests (k6)

The k6 scenarios in `load-tests/booking.js` cover four traffic shapes. Key assertions per scenario:

### Scenario 1: Smoke (`make load-test-smoke`)

```
VUs: 1  |  Duration: 30s  |  Purpose: sanity check before load test
```

Pass criteria:
- All requests succeed (0% error rate)
- Hold latency P99 < 200ms

### Scenario 2: Load (`make load-test`)

```
VUs: 50  |  Ramp: 1m up → 3m sustained → 1m down  |  Purpose: sustained throughput
```

Pass criteria:
- Error rate (5xx) < 1%
- Hold latency P99 < 100ms (SLO)
- Hold latency P50 < 20ms

### Scenario 3: Spike (`make load-test-spike`)

```
VUs: 10 → 200 (10s ramp) → 10 (immediate drop)  |  Purpose: burst traffic
```

Pass criteria:
- Service recovers within 30s of spike
- No 500 errors (409s are expected and acceptable during spike)

### Scenario 4: Concurrent Hold (`make load-test-concurrent`)

```
VUs: 500  |  All targeting the same 120 seats  |  Purpose: Redis NX lock validation
```

Pass criteria:
- Each seat booked at most once (0 double-bookings)
- 409 conflict responses expected and not counted as errors
- Redis memory stable (no leak)

### k6 Threshold Configuration

```javascript
// load-tests/booking.js — thresholds block
export const options = {
  thresholds: {
    // P99 hold latency SLO
    'http_req_duration{name:hold}': ['p(99)<100'],
    // Error rate (excludes 409 — expected conflicts)
    'http_req_failed{name:hold}': ['rate<0.01'],
    // Availability (seat map)
    'http_req_duration{name:availability}': ['p(95)<50'],
  },
};
```

---

## 9. Frontend Tests

The current frontend has zero tests. The Phase 8 architecture provides testable units via extracted hooks.

### State Machine Tests

```typescript
// features/booking/machine/bookingReducer.test.ts
import { bookingReducer } from "./bookingReducer";

describe("bookingReducer", () => {
  it("idle → SELECT_SEAT → selecting", () => {
    const state = bookingReducer({ stage: "idle" }, { type: "SELECT_SEAT", seatID: "A1" });
    expect(state).toEqual({ stage: "selecting", selectedSeats: ["A1"] });
  });

  it("checkout → CANCEL → idle", () => {
    const checkout = { stage: "checkout" as const, reservation: mockReservation, selectedSeats: ["A1"] };
    const state = bookingReducer(checkout, { type: "CANCEL" });
    expect(state).toEqual({ stage: "idle" });
  });

  it("paying → CONFIRM_SUCCESS → confirmed", () => {
    const paying = { stage: "paying" as const, reservation: mockReservation, payExpiresAt: 9999999999 };
    const state = bookingReducer(paying, {
      type: "CONFIRM_SUCCESS", bookingId: "bkg_1", totalCents: 2400,
    });
    expect(state.stage).toBe("confirmed");
  });

  it("confirmed is a terminal state", () => {
    const confirmed = { stage: "confirmed" as const, bookingId: "bkg_1", seatIDs: [], totalCents: 0 };
    const after = bookingReducer(confirmed, { type: "SELECT_SEAT", seatID: "A1" });
    expect(after).toEqual(confirmed); // no transition
  });
});
```

### Hook Tests (React Testing Library + Vitest)

```typescript
// features/booking/hooks/useCountdown.test.ts
import { renderHook, act } from "@testing-library/react";
import { vi } from "vitest";
import { useCountdown } from "./useCountdown";

it("displays MM:SS format", () => {
  vi.useFakeTimers();
  const expiresAt = Math.floor(Date.now() / 1000) + 125; // 2m 5s from now

  const { result } = renderHook(() => useCountdown(expiresAt));
  expect(result.current.display).toBe("02:05");
  vi.useRealTimers();
});

it("isUrgent when remaining < 60s", () => {
  vi.useFakeTimers();
  const expiresAt = Math.floor(Date.now() / 1000) + 30;
  const { result } = renderHook(() => useCountdown(expiresAt));
  expect(result.current.isUrgent).toBe(true);
  vi.useRealTimers();
});
```

---

## 10. Test Helpers and Builders

Test builders reduce boilerplate and make test intent clear.

```go
// tests/builders/booking_builder.go
package builders

type BookingBuilder struct {
    screeningID string
    userID      string
    seatIDs     []string
    totalCents  int64
    currency    string
}

func ABooking() *BookingBuilder {
    return &BookingBuilder{
        screeningID: "scr_test",
        userID:      "user_test",
        seatIDs:     []string{"A1"},
        totalCents:  1200,
        currency:    "USD",
    }
}

func (b *BookingBuilder) ForScreening(id string) *BookingBuilder {
    b.screeningID = id; return b
}

func (b *BookingBuilder) WithSeats(seats ...string) *BookingBuilder {
    b.seatIDs = seats; return b
}

func (b *BookingBuilder) Build() *domain.Booking {
    return domain.NewBooking(b.screeningID, b.userID, b.seatIDs,
        shared.MustMoney(b.totalCents, b.currency))
}

func (b *BookingBuilder) Confirmed() *domain.Booking {
    bk := b.Build()
    _ = bk.Confirm()
    return bk
}
```

Usage:
```go
booking := builders.ABooking().ForScreening("scr_1").WithSeats("A1", "A2").Confirmed()
```

---

## 11. Coverage Targets and Measurement

### Targets

| Package | Target | Rationale |
|---|---|---|
| `domain/booking` | 100% | Pure functions — no excuses |
| `domain/movie` | 100% | Pure functions — no excuses |
| `domain/shared` | 100% | Pure functions — no excuses |
| `application/booking` | 90% | Service logic is high-value |
| `application/movie` | 85% | Less complex than booking |
| `interfaces/http/handler` | 80% | HTTP contract coverage |
| `interfaces/http/middleware` | 70% | Middleware logic |
| `infrastructure/persistence` | 70% | Integration tests cover the rest |
| `cmd/api` | Excluded | Wiring code — hard to unit test |

**Overall project target: 80%** (excluding `cmd/` and generated code).

### Measurement

```bash
# Run unit tests with coverage
make test-unit  # → go test -count=1 ./internal/...

# Generate coverage report
go test -coverprofile=coverage.out -covermode=atomic ./internal/...
go tool cover -func=coverage.out                          # total per package
go tool cover -html=coverage.out -o coverage.html         # visual report

# Enforce minimum coverage (CI)
TOTAL=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | tr -d '%')
if (( $(echo "$TOTAL < 80" | bc -l) )); then
  echo "Coverage ${TOTAL}% is below 80% threshold"
  exit 1
fi
```

### What NOT to measure

Exclude from coverage:
- `cmd/api/main.go` — wiring; errors here are caught at startup
- `infrastructure/seeder/` — one-shot data seeding
- Generated BSON marshalling code
- Test helpers themselves (`tests/builders/`, `_test.go` support files)

---

## 12. CI Pipeline

```yaml
# .github/workflows/ci.yml

jobs:
  unit-tests:
    name: Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.23" }
      - run: cd backend && make test-unit
      - run: |
          cd backend
          go test -coverprofile=coverage.out -covermode=atomic ./internal/...
          TOTAL=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | tr -d '%')
          echo "Coverage: ${TOTAL}%"
          [ $(echo "$TOTAL >= 80" | bc -l) = 1 ] || exit 1

  race-detector:
    name: Race Detector
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: cd backend && make run-race  # go test -race -count=1 ./internal/...

  integration-tests:
    name: Integration Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - name: Install Docker  # testcontainers needs Docker
        uses: docker/setup-buildx-action@v3
      - run: cd backend && make test-integration

  frontend-tests:
    name: Frontend Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "22" }
      - run: cd frontend && npm ci && npm run test

  type-check:
    name: Type Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: cd frontend && npm ci && npm run type-check
```

**Job dependencies**:
- `race-detector` runs in parallel with `unit-tests` (same code, different guarantees)
- `integration-tests` requires Docker — runs in parallel but slower (~2m vs ~30s for unit)
- Load tests are NOT in CI — run manually via `make load-test` before releases

---

## 13. Test File Locations

```
backend/
  internal/
    domain/
      booking/
        booking_test.go              ← unit tests alongside source
        seat_test.go
        errors_test.go
      movie/
        movie_test.go
      shared/
        money_test.go
    application/
      booking/
        service_test.go              ← unit tests with mocks
      movie/
        service_test.go
    interfaces/http/handler/
      booking_handler_test.go        ← httptest handler tests
      movie_handler_test.go
      admin_handler_test.go
    infrastructure/persistence/
      redis/
        seat_lock_repository_test.go ← integration (testcontainers)
      mongodb/
        booking_repository_test.go   ← integration (testcontainers)
        movie_repository_test.go
        screening_repository_test.go
  tests/
    integration/
      redis_seat_lock_test.go        ← existing concurrency tests
      concurrency_test.go            ← new: RC-01, RC-02, RC-03, compensation
      e2e_test.go                    ← full stack: hold → confirm → history
    builders/
      booking_builder.go
      screening_builder.go
      movie_builder.go

frontend/
  src/
    features/
      booking/
        machine/
          bookingReducer.test.ts
        hooks/
          useCountdown.test.ts
          useBookingFlow.test.ts
        components/
          SeatGrid.test.tsx
    components/
      common/
        ErrorBoundary.test.tsx
```
