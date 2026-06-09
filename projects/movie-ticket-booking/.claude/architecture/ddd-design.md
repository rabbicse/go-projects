# DDD Design

_Phase 3 — Formal bounded context specifications — 2026-06-09_  
_Builds on: domain-model.md (Phase 2), architecture-review.md (Phase 1)_

---

## 1. Design Principles

Rules this design enforces:

1. **Domain knows nothing outside itself** — no framework imports, no JSON tags, no Redis/Mongo types in `domain/`
2. **Aggregates own their identity** — ID generated inside the constructor, never assigned externally
3. **Aggregates emit, services collect** — domain events are returned from methods as `[]DomainEvent`, not published directly
4. **Value objects are immutable** — no setters; all mutations return new instances
5. **Typed IDs everywhere** — `BookingID`, `UserID`, `ReservationID` instead of `string`
6. **Repository interfaces live in the domain** — infrastructure implements them; domain defines the contract
7. **Application services are thin** — they orchestrate; they don't contain business logic
8. **Commands mutate, Queries read** — CQRS-lite: separate input types, same service struct for now (full CQRS in Phase 7+)
9. **Contexts share a Shared Kernel, not entities** — `Money` and `UserID` cross context boundaries; `User` aggregate does not

---

## 2. Go Package Layout (Target)

```
backend/internal/

  shared/                          ← Shared Kernel (crosses all contexts)
    money.go                       # Money VO
    user_id.go                     # UserID VO
    pagination.go                  # Pagination params
    events.go                      # DomainEvent interface

  domain/
    catalog/                       ← Catalog Bounded Context
      movie.go                     # Movie AR + AddScreening invariant
      screening.go                 # Screening entity
      seat_layout.go               # SeatLayout VO
      genre.go                     # Genre VO
      errors.go
      repository.go                # CatalogRepository interface
    reservation/                   ← Reservation Bounded Context
      reservation.go               # SeatReservation AR
      seat.go                      # ReservedSeat VO
      reservation_id.go            # ReservationID VO
      status.go                    # ReservationStatus enum
      events.go                    # SeatsReserved, Confirmed, Released, Expired
      errors.go
      repository.go                # SeatReservationRepository interface
    booking/                       ← Booking Bounded Context
      booking.go                   # Booking AR
      booking_id.go                # BookingID VO
      seat.go                      # BookedSeat VO
      status.go                    # BookingStatus enum
      events.go                    # BookingCreated, Confirmed, Cancelled
      errors.go
      repository.go                # BookingRepository interface
    identity/                      ← Identity Bounded Context (stub)
      user.go                      # User AR
      errors.go
      repository.go

  application/
    catalog/
      service.go                   # ListMovies, GetScreening, CreateMovie, CreateScreening
    reservation/
      service.go                   # ReserveSeats, ConfirmReservation, CancelReservation, GetAvailability
      commands.go                  # ReserveSeatsCommand, ConfirmReservationCommand, ...
      queries.go                   # GetAvailabilityQuery
    booking/
      service.go                   # GetUserBookings, GetBooking
      queries.go                   # GetUserBookingsQuery
    identity/
      service.go                   # GetOrCreateUser (stub)

  infrastructure/
    persistence/
      redis/
        seat_reservation_repo.go   # SeatReservationRepository (Lua scripts)
        client.go
      mongodb/
        booking_repo.go            # BookingRepository
        catalog_repo.go            # CatalogRepository (movies + screenings)
        client.go
    events/
      dispatcher.go                # In-process domain event dispatcher
    seeder/
      seeder.go

  interfaces/
    http/
      handler/
        catalog_handler.go         # GET /movies, GET /movies/:id, GET /screenings/:id
        reservation_handler.go     # POST /hold, DELETE /sessions/:id
        booking_handler.go         # PUT /sessions/:id/confirm, GET /users/:id/bookings
        admin_handler.go           # POST /admin/movies, POST /admin/screenings
      dto/
        catalog_dto.go
        reservation_dto.go
        booking_dto.go
      middleware/
        logger.go
        cors.go
        ratelimit.go               # To be added
        request_id.go              # To be added
      router.go

  config/
    config.go

  cmd/api/
    main.go
```

---

## 3. Shared Kernel

### `shared/events.go`
```go
package shared

// DomainEvent is the marker interface for all domain events.
type DomainEvent interface {
    EventName() string
    OccurredAt() time.Time
}

// EventBase provides common fields for embedding in concrete events.
type EventBase struct {
    Name string
    At   time.Time
}
func (e EventBase) EventName() string    { return e.Name }
func (e EventBase) OccurredAt() time.Time { return e.At }
```

### `shared/money.go`
```go
package shared

type Money struct {
    cents    int64
    currency string
}
func NewMoney(cents int64, currency string) (Money, error) // validates currency
func USD(cents int64) Money
func (m Money) Add(other Money) (Money, error)     // returns error, no panic
func (m Money) Multiply(n int) Money
func (m Money) Cents() int64
func (m Money) Currency() string
func (m Money) IsZero() bool
```

### `shared/user_id.go`
```go
package shared

type UserID struct{ value string }
func NewUserID(v string) (UserID, error)  // validates non-empty UUID format
func (u UserID) String() string
func (u UserID) IsZero() bool
```

### `shared/pagination.go`
```go
package shared

type Pagination struct {
    Page     int  // 1-based
    PageSize int  // default 20, max 100
}
func (p Pagination) Offset() int
func DefaultPagination() Pagination
```

---

## 4. Catalog Bounded Context

### Ubiquitous Language

| Term | Meaning |
|---|---|
| Movie | A film title available in the cinema's catalog |
| Screening | A single scheduled showing of a Movie in a specific Screen |
| Screen | A physical room/hall with a fixed seat layout |
| SeatLayout | The grid dimensions of a Screen (rows × seatsPerRow) |
| Genre | A category tag for a Movie |

### Aggregates

#### `domain/catalog/movie.go`
```go
package catalog

import (
    "errors"
    "time"
    "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

type Movie struct {
    ID          string
    Title       string
    Genres      []Genre
    Rating      float64
    PosterURL   string
    Description string
    DurationMin int
    screenings  []Screening  // unexported — accessed via methods
    createdAt   time.Time
}

// AddScreening enforces the hall-overlap invariant.
// Returns ErrScreeningConflict if the hall already has an overlapping screening.
func (m *Movie) AddScreening(s Screening) error {
    if s.MovieID != m.ID {
        return ErrScreeningMovieMismatch
    }
    for _, existing := range m.screenings {
        if existing.Screen == s.Screen && timesOverlap(existing.StartTime, existing.EndTime, s.StartTime, s.EndTime) {
            return ErrScreeningConflict
        }
    }
    m.screenings = append(m.screenings, s)
    return nil
}

func (m *Movie) Screenings() []Screening { return append([]Screening{}, m.screenings...) }

func (m *Movie) FindScreening(id string) (Screening, bool) {
    for _, s := range m.screenings {
        if s.ID == id { return s, true }
    }
    return Screening{}, false
}
```

#### `domain/catalog/screening.go`
```go
package catalog

import (
    "time"
    "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

// Screening is an entity owned by Movie.
// "Showtime" in the old codebase.
type Screening struct {
    ID         string
    MovieID    string
    Screen     string        // "Hall A" — will become Screen entity in full impl
    StartTime  time.Time
    EndTime    time.Time
    Layout     SeatLayout
    Price      shared.Money
}

func (s Screening) TotalSeats() int { return s.Layout.TotalSeats() }
func (s Screening) Duration() time.Duration { return s.EndTime.Sub(s.StartTime) }
```

#### `domain/catalog/seat_layout.go`
```go
package catalog

import "fmt"

// SeatLayout is an immutable value object describing a screen's seat grid.
type SeatLayout struct {
    Rows        int
    SeatsPerRow int
}

func NewSeatLayout(rows, seatsPerRow int) (SeatLayout, error) {
    if rows < 1 || rows > 26 {
        return SeatLayout{}, fmt.Errorf("rows must be 1–26, got %d", rows)
    }
    if seatsPerRow < 1 {
        return SeatLayout{}, fmt.Errorf("seatsPerRow must be >= 1")
    }
    return SeatLayout{Rows: rows, SeatsPerRow: seatsPerRow}, nil
}

func (l SeatLayout) TotalSeats() int { return l.Rows * l.SeatsPerRow }

// SeatIDAt returns the canonical seat ID for row r (0-based), seat s (0-based).
func (l SeatLayout) SeatIDAt(row, seat int) string {
    return fmt.Sprintf("%c%d", 'A'+rune(row), seat+1)
}
```

#### `domain/catalog/errors.go`
```go
package catalog

import "errors"

var (
    ErrMovieNotFound          = errors.New("movie not found")
    ErrScreeningNotFound      = errors.New("screening not found")
    ErrScreeningConflict      = errors.New("screening conflicts with existing screening in same screen")
    ErrScreeningMovieMismatch = errors.New("screening does not belong to this movie")
)
```

#### `domain/catalog/repository.go`
```go
package catalog

import "context"

type Repository interface {
    FindAll(ctx context.Context) ([]Movie, error)
    FindByID(ctx context.Context, movieID string) (Movie, error)
    FindScreening(ctx context.Context, screeningID string) (Screening, error)
    Save(ctx context.Context, m Movie) error
    SaveScreening(ctx context.Context, s Screening) error
    UpsertMany(ctx context.Context, movies []Movie) error
}
```

### Application Service

#### `application/catalog/commands.go`
```go
package catalog

type CreateMovieCommand struct {
    ID          string
    Title       string
    Genres      []string
    Rating      float64
    PosterURL   string
    Description string
    DurationMin int
}

type CreateScreeningCommand struct {
    ID          string
    MovieID     string
    Screen      string
    StartTime   time.Time
    EndTime     time.Time
    Rows        int
    SeatsPerRow int
    PriceCents  int64
    Currency    string
}
```

#### `application/catalog/service.go`
```go
package catalog

type Service struct {
    repo domain.Repository  // domain/catalog.Repository
}

func (s *Service) ListMovies(ctx context.Context) ([]domain.Movie, error)
func (s *Service) GetMovie(ctx context.Context, id string) (domain.Movie, error)
func (s *Service) GetScreening(ctx context.Context, id string) (domain.Screening, error)
func (s *Service) CreateMovie(ctx context.Context, cmd CreateMovieCommand) error
// CreateScreening LOADS the Movie aggregate, calls AddScreening, then saves.
// This enforces the hall-overlap invariant. Fixes current AP-05.
func (s *Service) CreateScreening(ctx context.Context, cmd CreateScreeningCommand) error
```

---

## 5. Reservation Bounded Context

### Ubiquitous Language

| Term | Meaning |
|---|---|
| SeatReservation | A time-bounded exclusive lock on specific seats for a specific user |
| ReservedSeat | A seat that is part of a reservation |
| Hold window | The TTL period during which a reservation is pending |
| Expiry | Automatic release of a reservation when the hold window closes |

### Aggregates

#### `domain/reservation/reservation.go`
```go
package reservation

import (
    "time"
    "github.com/google/uuid"
    "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

type SeatReservation struct {
    ID          ReservationID
    UserID      shared.UserID
    ScreeningID string
    Seats       []ReservedSeat
    Status      ReservationStatus
    ExpiresAt   time.Time
    CreatedAt   time.Time
    events      []shared.DomainEvent  // unexported
}

// New creates a pending reservation. ID is self-assigned.
func New(userID shared.UserID, screeningID string, seats []ReservedSeat, holdTTL time.Duration) (SeatReservation, error) {
    if len(seats) == 0 {
        return SeatReservation{}, ErrNoSeatsSelected
    }
    now := time.Now().UTC()
    r := SeatReservation{
        ID:          ReservationID(uuid.New().String()),
        UserID:      userID,
        ScreeningID: screeningID,
        Seats:       seats,
        Status:      StatusPending,
        ExpiresAt:   now.Add(holdTTL),
        CreatedAt:   now,
    }
    r.events = append(r.events, SeatsReserved{
        EventBase:     shared.EventBase{Name: "SeatsReserved", At: now},
        ReservationID: r.ID,
        ScreeningID:   screeningID,
        UserID:        userID,
        SeatIDs:       r.SeatIDs(),
        ExpiresAt:     r.ExpiresAt,
    })
    return r, nil
}

func (r *SeatReservation) Confirm() error {
    if r.Status != StatusPending {
        return ErrInvalidStatusTransition
    }
    if time.Now().UTC().After(r.ExpiresAt) {
        return ErrReservationExpired
    }
    r.Status = StatusConfirmed
    r.events = append(r.events, ReservationConfirmed{
        EventBase:     shared.EventBase{Name: "ReservationConfirmed", At: time.Now().UTC()},
        ReservationID: r.ID,
        UserID:        r.UserID,
        ScreeningID:   r.ScreeningID,
        SeatIDs:       r.SeatIDs(),
    })
    return nil
}

func (r *SeatReservation) Release() error {
    if r.Status != StatusPending {
        return ErrInvalidStatusTransition
    }
    r.Status = StatusReleased
    r.events = append(r.events, ReservationReleased{
        EventBase:     shared.EventBase{Name: "ReservationReleased", At: time.Now().UTC()},
        ReservationID: r.ID,
    })
    return nil
}

func (r *SeatReservation) Expire() error {
    if r.Status != StatusPending {
        return ErrInvalidStatusTransition
    }
    r.Status = StatusExpired
    r.events = append(r.events, ReservationExpired{
        EventBase:     shared.EventBase{Name: "ReservationExpired", At: time.Now().UTC()},
        ReservationID: r.ID,
    })
    return nil
}

// PopEvents returns and clears accumulated domain events.
func (r *SeatReservation) PopEvents() []shared.DomainEvent {
    evts := r.events
    r.events = nil
    return evts
}

func (r *SeatReservation) SeatIDs() []string {
    ids := make([]string, len(r.Seats))
    for i, s := range r.Seats { ids[i] = s.ID }
    return ids
}
```

#### `domain/reservation/reservation_id.go`
```go
package reservation

type ReservationID string

func (id ReservationID) String() string { return string(id) }
func (id ReservationID) IsZero() bool   { return id == "" }
```

#### `domain/reservation/seat.go`
```go
package reservation

import (
    "fmt"
    "strings"
)

// ReservedSeat is a value object. Identical structure to old booking.Seat.
type ReservedSeat struct {
    ID     string
    Row    string
    Number int
}

func NewReservedSeat(id string) (ReservedSeat, error) {
    id = strings.ToUpper(strings.TrimSpace(id))
    if len(id) < 2 { return ReservedSeat{}, fmt.Errorf("invalid seat id %q", id) }
    row := string(id[0])
    if row < "A" || row > "Z" { return ReservedSeat{}, fmt.Errorf("invalid row in %q", id) }
    var num int
    if _, err := fmt.Sscanf(id[1:], "%d", &num); err != nil || num < 1 {
        return ReservedSeat{}, fmt.Errorf("invalid number in %q", id)
    }
    return ReservedSeat{ID: id, Row: row, Number: num}, nil
}
```

#### `domain/reservation/status.go`
```go
package reservation

type ReservationStatus string

const (
    StatusPending   ReservationStatus = "pending"
    StatusConfirmed ReservationStatus = "confirmed"
    StatusReleased  ReservationStatus = "released"
    StatusExpired   ReservationStatus = "expired"
)
```

#### `domain/reservation/events.go`
```go
package reservation

import (
    "time"
    "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

type SeatsReserved struct {
    shared.EventBase
    ReservationID ReservationID
    ScreeningID   string
    UserID        shared.UserID
    SeatIDs       []string
    ExpiresAt     time.Time
}

type ReservationConfirmed struct {
    shared.EventBase
    ReservationID ReservationID
    UserID        shared.UserID
    ScreeningID   string
    SeatIDs       []string
}

type ReservationReleased struct {
    shared.EventBase
    ReservationID ReservationID
}

type ReservationExpired struct {
    shared.EventBase
    ReservationID ReservationID
}
```

#### `domain/reservation/errors.go`
```go
package reservation

import "errors"

var (
    ErrNoSeatsSelected        = errors.New("at least one seat must be selected")
    ErrMaxSeatsExceeded       = errors.New("number of seats exceeds the maximum allowed per reservation")
    ErrSeatAlreadyReserved    = errors.New("one or more seats are already reserved")
    ErrReservationNotFound    = errors.New("reservation not found or expired")
    ErrReservationExpired     = errors.New("reservation has expired")
    ErrUnauthorized           = errors.New("reservation does not belong to this user")
    ErrInvalidStatusTransition = errors.New("invalid reservation status transition")
)
```

#### `domain/reservation/repository.go`
```go
package reservation

import "context"

// SeatAvailability is defined here (not in domain as a JSON DTO — fixing SM-05).
type SeatAvailability struct {
    SeatID       string
    Status       ReservationStatus
    ReservedByMe bool            // true when the requesting user holds this seat
    ExpiresAt    *time.Time      // non-nil only when Status == Pending
}

type Repository interface {
    // Reserve atomically locks all seats (Lua NX) and persists the reservation.
    // Returns ErrSeatAlreadyReserved if any seat is taken.
    Reserve(ctx context.Context, r SeatReservation) error

    FindByID(ctx context.Context, id ReservationID) (SeatReservation, error)

    // Confirm removes TTLs from seat keys and session key (makes locks permanent).
    Confirm(ctx context.Context, id ReservationID) error

    // Release deletes all seat keys and the reservation key.
    Release(ctx context.Context, id ReservationID) error

    // GetAvailability returns real-time seat status for a screening.
    // userID is used to mark ReservedByMe; pass zero value to skip.
    GetAvailability(ctx context.Context, screeningID string, userID shared.UserID) ([]SeatAvailability, error)
}
```

### Application Service

#### `application/reservation/commands.go`
```go
package reservation

import "github.com/rabbicse/movie-ticket-booking/internal/shared"

type ReserveSeatsCommand struct {
    UserID      shared.UserID
    ScreeningID string
    SeatIDs     []string
}

type ConfirmReservationCommand struct {
    ReservationID string
    UserID        shared.UserID
}

type CancelReservationCommand struct {
    ReservationID string
    UserID        shared.UserID
}
```

#### `application/reservation/queries.go`
```go
package reservation

import "github.com/rabbicse/movie-ticket-booking/internal/shared"

type GetAvailabilityQuery struct {
    ScreeningID string
    UserID      shared.UserID  // zero value = anonymous viewer
}
```

#### `application/reservation/service.go`
```go
package reservation

// Service orchestrates the reservation flow.
// It does NOT contain business logic — that lives in the domain aggregate.
type Service struct {
    reservationRepo domain.Repository       // domain/reservation.Repository
    catalogRepo     catalog.Repository      // domain/catalog.Repository (ACL)
    eventDispatcher events.Dispatcher
    maxSeats        int
    holdTTL         time.Duration
}

func (s *Service) ReserveSeats(ctx context.Context, cmd ReserveSeatsCommand) (domain.SeatReservation, error)
    // 1. Validate command (seat count, seat ID format)
    // 2. Fetch screening from catalog repo (ACL: cross-context read)
    // 3. Build []ReservedSeat from cmd.SeatIDs
    // 4. Call domain.New() → reservation + events
    // 5. Call reservationRepo.Reserve() (atomic Lua)
    // 6. Dispatch events (SeatsReserved → BookingService creates held record)
    // 7. Return reservation

func (s *Service) ConfirmReservation(ctx context.Context, cmd ConfirmReservationCommand) error
    // 1. FindByID (Redis)
    // 2. Verify ownership
    // 3. reservation.Confirm() → domain validates expiry + status
    // 4. reservationRepo.Confirm() (Redis PERSIST)
    // 5. Dispatch ReservationConfirmed event

func (s *Service) CancelReservation(ctx context.Context, cmd CancelReservationCommand) error
    // 1. FindByID (Redis)
    // 2. Verify ownership
    // 3. reservation.Release()
    // 4. reservationRepo.Release()
    // 5. Dispatch ReservationReleased event

func (s *Service) GetAvailability(ctx context.Context, q GetAvailabilityQuery) ([]domain.SeatAvailability, error)
```

---

## 6. Booking Bounded Context

### Ubiquitous Language

| Term | Meaning |
|---|---|
| Booking | The confirmed (or in-progress) purchase record — the receipt |
| BookingID | Globally unique identifier for a booking |
| BookedSeat | A seat that is part of a booking record |

### Aggregates

#### `domain/booking/booking.go`
```go
package booking

import (
    "time"
    "github.com/google/uuid"
    "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

type Booking struct {
    ID            BookingID
    ReservationID string             // link to Reservation context
    UserID        shared.UserID
    ScreeningID   string
    MovieID       string
    Seats         []BookedSeat
    Status        BookingStatus
    TotalPrice    shared.Money
    CreatedAt     time.Time
    UpdatedAt     time.Time
    ExpiresAt     time.Time
    ConfirmedAt   *time.Time
    events        []shared.DomainEvent
}

// New creates a booking in Held status. ID is self-assigned. Fixes SM-10.
func New(reservationID string, userID shared.UserID, screeningID, movieID string,
    seats []BookedSeat, pricePerSeat shared.Money, holdTTL time.Duration) (Booking, error) {

    if len(seats) == 0 { return Booking{}, ErrNoSeatsSelected }
    total, err := pricePerSeat.Multiply(len(seats))
    if err != nil { return Booking{}, err }
    now := time.Now().UTC()
    b := Booking{
        ID:            BookingID(uuid.New().String()),  // self-assigned — fixes AP-10
        ReservationID: reservationID,
        UserID:        userID,
        ScreeningID:   screeningID,
        MovieID:       movieID,
        Seats:         seats,
        Status:        StatusHeld,
        TotalPrice:    total,
        CreatedAt:     now,
        UpdatedAt:     now,
        ExpiresAt:     now.Add(holdTTL),
    }
    b.events = append(b.events, BookingCreated{
        EventBase: shared.EventBase{Name: "BookingCreated", At: now},
        BookingID: b.ID, UserID: userID, ReservationID: reservationID,
    })
    return b, nil
}

func (b *Booking) Confirm() error {
    if b.Status != StatusHeld { return ErrInvalidStatusTransition }
    if time.Now().UTC().After(b.ExpiresAt) { return ErrBookingExpired }
    now := time.Now().UTC()
    b.Status = StatusConfirmed
    b.UpdatedAt = now
    b.ConfirmedAt = &now
    b.events = append(b.events, BookingConfirmed{
        EventBase:  shared.EventBase{Name: "BookingConfirmed", At: now},
        BookingID:  b.ID,
        UserID:     b.UserID,
        TotalPrice: b.TotalPrice,
    })
    return nil
}

func (b *Booking) Cancel() error {
    if b.Status != StatusHeld { return ErrInvalidStatusTransition }
    b.Status = StatusCancelled
    b.UpdatedAt = time.Now().UTC()
    b.events = append(b.events, BookingCancelled{
        EventBase: shared.EventBase{Name: "BookingCancelled", At: b.UpdatedAt},
        BookingID: b.ID,
    })
    return nil
}

// Expire marks a held booking as expired. Fixes SM-12 (StatusExpired never set).
func (b *Booking) Expire() error {
    if b.Status != StatusHeld { return ErrInvalidStatusTransition }
    b.Status = StatusExpired
    b.UpdatedAt = time.Now().UTC()
    return nil
}

func (b *Booking) PopEvents() []shared.DomainEvent {
    evts := b.events
    b.events = nil
    return evts
}

func (b *Booking) SeatIDs() []string {
    ids := make([]string, len(b.Seats))
    for i, s := range b.Seats { ids[i] = s.ID }
    return ids
}
```

#### `domain/booking/booking_id.go`
```go
package booking

type BookingID string

func (id BookingID) String() string { return string(id) }
func (id BookingID) IsZero() bool   { return id == "" }
```

#### `domain/booking/status.go`
```go
package booking

type BookingStatus string

const (
    StatusHeld      BookingStatus = "held"
    StatusConfirmed BookingStatus = "confirmed"
    StatusCancelled BookingStatus = "cancelled"
    StatusExpired   BookingStatus = "expired"
)
```

#### `domain/booking/events.go`
```go
package booking

import (
    "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

type BookingCreated struct {
    shared.EventBase
    BookingID     BookingID
    UserID        shared.UserID
    ReservationID string
}

type BookingConfirmed struct {
    shared.EventBase
    BookingID  BookingID
    UserID     shared.UserID
    TotalPrice shared.Money
}

type BookingCancelled struct {
    shared.EventBase
    BookingID BookingID
}
```

#### `domain/booking/repository.go`
```go
package booking

import (
    "context"
    "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

type Repository interface {
    Save(ctx context.Context, b Booking) error
    Update(ctx context.Context, b Booking) error
    FindByID(ctx context.Context, id BookingID) (Booking, error)
    FindByReservationID(ctx context.Context, reservationID string) (Booking, error)
    // Paginated — fixes TD-07
    FindByUserID(ctx context.Context, userID shared.UserID, p shared.Pagination) ([]Booking, int, error)
    FindByScreening(ctx context.Context, screeningID string) ([]Booking, error)
}
```

### Application Service

#### `application/booking/service.go`
```go
package booking

// BookingService handles query-side operations.
// Write operations (create, confirm, cancel) are triggered by domain events
// from the Reservation context via the event dispatcher.
type Service struct {
    bookingRepo domain.Repository
}

func (s *Service) GetBooking(ctx context.Context, id domain.BookingID) (domain.Booking, error)
func (s *Service) GetUserBookings(ctx context.Context, userID shared.UserID, p shared.Pagination) ([]domain.Booking, int, error)
```

#### Event Handlers (driven by Reservation events)

```go
// application/booking/event_handlers.go

type ReservationEventHandler struct {
    bookingRepo    domain.Repository
    catalogRepo    catalog.Repository   // to get screening price
    holdTTL        time.Duration
}

// OnSeatsReserved creates a held booking record when a reservation is created.
func (h *ReservationEventHandler) OnSeatsReserved(ctx context.Context, evt reservation.SeatsReserved) error

// OnReservationConfirmed confirms the booking record.
func (h *ReservationEventHandler) OnReservationConfirmed(ctx context.Context, evt reservation.ReservationConfirmed) error

// OnReservationReleased marks booking as cancelled.
func (h *ReservationEventHandler) OnReservationReleased(ctx context.Context, evt reservation.ReservationReleased) error
```

---

## 7. Identity Bounded Context (Stub)

### `domain/identity/user.go`
```go
package identity

import (
    "time"
    "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

// User is the aggregate root for the Identity context.
// Minimal for now — expands when auth is added.
type User struct {
    ID        shared.UserID
    CreatedAt time.Time
}

// GetOrCreate is a factory: returns existing user or creates a new one.
// Called when a userID from the client is first seen.
```

### `domain/identity/repository.go`
```go
package identity

import (
    "context"
    "github.com/rabbicse/movie-ticket-booking/internal/shared"
)

type Repository interface {
    FindByID(ctx context.Context, id shared.UserID) (User, error)
    Save(ctx context.Context, u User) error
}
```

---

## 8. Payment Bounded Context (Stub)

Placeholder only — no implementation in current scope.

```go
// domain/payment/payment.go
type Payment struct {
    ID          PaymentID
    BookingID   booking.BookingID
    Amount      shared.Money
    Status      PaymentStatus
    ProcessedAt *time.Time
}

type PaymentStatus string
const (
    PaymentPending   PaymentStatus = "pending"
    PaymentSucceeded PaymentStatus = "succeeded"
    PaymentFailed    PaymentStatus = "failed"
    PaymentRefunded  PaymentStatus = "refunded"
)
```

The current "Pay Now → confirm" flow maps to `PaymentSucceeded` being emitted immediately as a simulated success. This makes the stub extension-ready: replace the simulation with a real payment gateway without changing the Booking context.

---

## 9. Cross-Context Communication

### Anti-Corruption Layer: Catalog → Reservation

The Reservation context needs screening price and layout when creating a reservation. It must not import catalog domain types directly (that would couple the contexts). Solution: the **application service** reads from the catalog repository and passes primitive values into the domain:

```go
// application/reservation/service.go

func (s *Service) ReserveSeats(ctx context.Context, cmd ReserveSeatsCommand) (domain.SeatReservation, error) {
    // ACL: read from catalog context
    screening, err := s.catalogRepo.FindScreening(ctx, cmd.ScreeningID)
    if err != nil { return ..., fmt.Errorf("screening not found: %w", err) }

    // Pass primitives to domain — no catalog types leak into reservation domain
    seats := buildReservedSeats(cmd.SeatIDs)
    r, err := domain.New(cmd.UserID, cmd.ScreeningID, seats, s.holdTTL)
    // ...
}
```

### Event-Driven: Reservation → Booking

```
ReservationService.ReserveSeats()
  → reservation.New()           emits SeatsReserved
  → reservationRepo.Reserve()   (Redis Lua)
  → dispatcher.Dispatch(events) → BookingEventHandler.OnSeatsReserved()
                                   → booking.New()
                                   → bookingRepo.Save()   (MongoDB)
```

### In-Process Event Dispatcher

```go
// infrastructure/events/dispatcher.go

type Handler func(ctx context.Context, event shared.DomainEvent) error

type Dispatcher struct {
    handlers map[string][]Handler
}

func (d *Dispatcher) Register(eventName string, h Handler)
func (d *Dispatcher) Dispatch(ctx context.Context, events []shared.DomainEvent) error
```

This is synchronous and in-process. It can be replaced by a message broker (NATS, Kafka) without changing the domain or application layers.

---

## 10. Key Design Decisions (ADR Pointers)

| Decision | Choice | Rationale |
|---|---|---|
| Event dispatch | Synchronous in-process | Simple; extend to async when needed |
| Context coupling | ACL via shared repo interface | Avoids DTO translation layer for simple reads |
| Aggregate ID | Self-assigned in constructor | Fixes AP-10; consistent with DDD |
| `StatusReleased` → `StatusCancelled` | Rename | "Release" is an implementation verb; "cancel" is the domain verb |
| Typed IDs | `BookingID`, `ReservationID`, `UserID` | Prevents assignment errors across types |
| Domain events | `PopEvents()` pattern | Services collect events after aggregate operations |
| Pagination | `shared.Pagination` | Fixes TD-07; consistent across all list queries |

---

## 11. Migration Delta from Current Code

| Current | Target | Change |
|---|---|---|
| `domain/booking.Session` | `domain/reservation.SeatReservation` | Promote to proper AR with events |
| `domain/booking.SeatStatus` | `domain/reservation.SeatAvailability` | Move out of domain; rename |
| `domain/movie.Showtime` | `domain/catalog.Screening` | Rename |
| `application/booking.HoldSeats` | `application/reservation.ReserveSeats` | Move to Reservation context |
| `application/booking.ConfirmBooking` | `application/reservation.ConfirmReservation` | Move; Booking updated via event |
| `booking.New()` with external ID | `booking.New()` self-assigns `BookingID` | Fixes AP-10 |
| `Status{Released}` | `Status{Cancelled}` | Domain language |
| No `Expire()` | `Expire()` on both aggregates | Fixes SM-12 |
| `Money.Add()` panic | `Money.Add()` returns error | Fixes SM-11 |
| maxSeats in handler | maxSeats only in service | Fixes AP-09 |
