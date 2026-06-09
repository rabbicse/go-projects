# Domain Model

_Phase 2 — Domain Discovery — 2026-06-09_

---

## 1. Domain Discovery Method

Domains were extracted by:
1. Reading all files under `backend/internal/domain/`, `application/`, and `infrastructure/`
2. Identifying nouns with lifecycle (aggregates), nouns without lifecycle (value objects), and verbs that cross aggregate boundaries (domain services / events)
3. Comparing against the cinema business domain to surface missing concepts the code currently elides

---

## 2. Validated Domain Objects (Current Codebase)

These exist today and are confirmed from source:

| Object | Kind | Package | Notes |
|---|---|---|---|
| `Movie` | Aggregate Root | `domain/movie` | Owns showtimes |
| `Showtime` | Entity | `domain/movie` | Owned by Movie; has identity (ID) |
| `Booking` | Aggregate Root | `domain/booking` | Main purchase record |
| `Seat` | Value Object | `domain/booking` | Immutable; validated format "A1" |
| `Money` | Value Object | `domain/shared` | Immutable; cents + currency |
| `Status` | Enum | `domain/booking` | Held / Confirmed / Released / Expired |
| `Session` | **Misplaced** | `domain/booking` | Redis ephemeral state — not a domain object |
| `SeatStatus` | **Misplaced** | `domain/booking` | HTTP DTO — not a domain object |

---

## 3. Missing Domain Objects (Gap Analysis)

The following business concepts exist in the real domain but are absent from the model:

| Missing Concept | Currently Represented As | Domain Significance |
|---|---|---|
| `User` | `string userID` | No identity, no ownership semantics, blocks auth |
| `Screen` / `Hall` | `string "Hall A"` | Physical venue with layout — should be an entity |
| `Reservation` | Split across Redis `Session` + `Booking.StatusHeld` | The hold window is a first-class aggregate |
| `Payment` | Simulated — confirm button calls confirm endpoint | Should be a context boundary |
| `Genre` | `[]string` | Value object (or enumeration) — not a plain string slice |
| `SeatLayout` | `rows int + seatsPerRow int` inline on Showtime | Value object for seat matrix |
| Domain Events | Absent | Status transitions emit no events |

---

## 4. Bounded Contexts

### 4.1 Catalog Context

**Purpose**: Manage the cinema's offering — what movies are showing, when, where, and at what price.  
**Change rate**: Low (catalog changes weekly, not per-request).  
**Owner**: Content / Programming team.

```
┌─────────────────────────────────────────────────────┐
│  CATALOG CONTEXT                                    │
│                                                     │
│  ┌─────────────────┐     owns     ┌──────────────┐ │
│  │  Movie           │─────────────►│  Screening   │ │
│  │  (Aggregate Root)│             │  (Entity)    │ │
│  └─────────────────┘             └──────────────┘ │
│         │                               │          │
│    has many                        has one         │
│         │                               │          │
│  ┌──────┴──────┐              ┌─────────┴──────┐  │
│  │  Genre      │              │  SeatLayout    │  │
│  │  (VO)       │              │  (VO)          │  │
│  └─────────────┘              └────────────────┘  │
│                                        │           │
│                                   has one          │
│                                        │           │
│                               ┌────────┴──────┐   │
│                               │  Screen       │   │
│                               │  (Entity)     │   │
│                               └───────────────┘   │
│                                                     │
│  Shared Kernel: Money (VO)                         │
└─────────────────────────────────────────────────────┘
```

**Aggregates**

##### `Movie` (Aggregate Root)
```
Identity:    string ID (slug: "dune-part-two")
Fields:      Title, Genre[], Rating, PosterURL, Description, DurationMin
Owns:        []Screening
Invariants:
  - A screening cannot be added if its hall overlaps with an existing screening time
  - All screenings must reference this movie's ID
Methods:     AddScreening(s), RemoveScreening(id), FindScreening(id)
```

##### `Screening` (Entity — owned by Movie)
> Renamed from `Showtime`. "Screening" is the correct cinema domain term for a scheduled showing of a film.

```
Identity:    string ID (slug: "dune2-hall1-1")
Fields:      MovieID, Screen, StartTime, EndTime, Price(Money), SeatLayout
Invariants:
  - EndTime must be after StartTime
  - SeatLayout rows and seatsPerRow must be > 0
  - Price must be positive
```

**Value Objects**

| VO | Fields | Invariants |
|---|---|---|
| `Genre` | `name string` | Non-empty, from allowed set |
| `SeatLayout` | `rows int, seatsPerRow int` | Both > 0; max rows ≤ 26 (A-Z) |
| `Screen` | `name string, capacity int` | Currently implicit; should be explicit |
| `Money` | `cents int64, currency string` | cents ≥ 0, currency ISO-4217 |

**Repository Interface**
```go
type ScreeningRepository interface {
    FindAll(ctx) ([]Movie, error)
    FindByID(ctx, movieID) (Movie, error)
    FindScreening(ctx, screeningID) (Screening, error)
    Save(ctx, Movie) error
    SaveScreening(ctx, Screening) error
    UpsertMany(ctx, []Movie) error
}
```

---

### 4.2 Reservation Context

**Purpose**: Manage the time-bounded exclusive lock on seats. Reservations are ephemeral — they live in Redis with a TTL. The invariant is: at most one reservation per seat per screening at any point in time.  
**Change rate**: Very high (per user interaction).  
**Owner**: Booking / Platform team.

```
┌──────────────────────────────────────────────────────────┐
│  RESERVATION CONTEXT                                     │
│                                                          │
│  ┌──────────────────────┐                               │
│  │  SeatReservation      │ ← Aggregate Root (ephemeral) │
│  │  (Aggregate Root)     │                              │
│  └──────────┬────────────┘                              │
│             │  holds                                     │
│  ┌──────────▼────────────┐    ┌────────────────────┐   │
│  │  ReservedSeat         │    │  ReservationStatus │   │
│  │  (Value Object)       │    │  Pending           │   │
│  └───────────────────────┘    │  Confirmed         │   │
│                               │  Released          │   │
│                               │  Expired           │   │
│                               └────────────────────┘   │
│                                                          │
│  Domain Events:                                          │
│    SeatsReserved(reservationID, screeningID, seatIDs)   │
│    ReservationConfirmed(reservationID)                   │
│    ReservationReleased(reservationID)                    │
│    ReservationExpired(reservationID)                     │
└──────────────────────────────────────────────────────────┘
```

**Aggregates**

##### `SeatReservation` (Aggregate Root)
> Replaces the current split between Redis `Session` and `Booking{Status: held}`. The hold window IS a first-class aggregate, not an implementation detail of the booking.

```
Identity:    ReservationID (UUID)
Fields:
  UserID       UserID (VO)
  ScreeningID  string
  Seats        []ReservedSeat
  Status       ReservationStatus
  ExpiresAt    time.Time
  CreatedAt    time.Time

Invariants:
  - Cannot confirm if status != Pending
  - Cannot confirm if time.Now().After(ExpiresAt)
  - Cannot release if status != Pending
  - Seats must be non-empty (min 1, max configurable)

Methods:
  Reserve(userID, screeningID, seats, ttl) → SeatReservation, []DomainEvent
  Confirm() → []DomainEvent
  Release() → []DomainEvent
  Expire() → []DomainEvent
```

**Value Objects**

| VO | Fields | Notes |
|---|---|---|
| `ReservedSeat` | `id string, row string, number int` | Same as current `Seat` VO |
| `ReservationID` | `uuid string` | Typed wrapper, not plain string |

**Repository Interface**
```go
type SeatReservationRepository interface {
    // Atomically reserve all seats or fail (Lua script)
    Reserve(ctx, SeatReservation) error
    // Returns ErrReservationNotFound if expired/missing
    FindByID(ctx, ReservationID) (SeatReservation, error)
    // Remove TTL — makes reservation permanent
    Confirm(ctx, ReservationID) error
    // Delete all seat keys and reservation key
    Release(ctx, ReservationID) error
    // Get real-time availability for a screening
    GetAvailability(ctx, screeningID string, forUserID UserID) ([]SeatAvailability, error)
}
```

---

### 4.3 Booking Context

**Purpose**: Maintain the authoritative audit trail of confirmed purchases. A booking record is the "receipt" — immutable once confirmed. Driven by events from the Reservation context.  
**Change rate**: Medium (created on hold, updated on confirm/release).  
**Owner**: Booking / Finance team.

```
┌──────────────────────────────────────────────────────────┐
│  BOOKING CONTEXT                                         │
│                                                          │
│  ┌──────────────────────┐                               │
│  │  Booking              │ ← Aggregate Root             │
│  │  (Aggregate Root)     │                              │
│  └──────────┬────────────┘                              │
│             │ contains                                   │
│  ┌──────────▼──────────┐   ┌──────────────────────┐    │
│  │  BookedSeat          │   │  BookingStatus       │    │
│  │  (Value Object)      │   │  Held                │    │
│  └──────────────────────┘   │  Confirmed           │    │
│                             │  Released            │    │
│  Shared Kernel:             │  Expired             │    │
│    Money (VO)               └──────────────────────┘    │
│                                                          │
│  Domain Events:                                          │
│    BookingCreated(bookingID, reservationID, userID)      │
│    BookingConfirmed(bookingID, totalPrice)               │
│    BookingCancelled(bookingID)                           │
└──────────────────────────────────────────────────────────┘
```

**Aggregates**

##### `Booking` (Aggregate Root)
```
Identity:    BookingID (UUID)
Fields:
  ReservationID  ReservationID    ← link to Reservation context
  UserID         UserID
  ScreeningID    string
  MovieID        string
  Seats          []BookedSeat
  Status         BookingStatus
  TotalPrice     Money
  CreatedAt      time.Time
  UpdatedAt      time.Time
  ExpiresAt      time.Time
  ConfirmedAt    *time.Time

Invariants:
  - Cannot confirm unless Status == Held
  - Cannot confirm after ExpiresAt
  - Cannot release unless Status == Held
  - TotalPrice == pricePerSeat × len(Seats)

Methods:
  New(reservationID, userID, screeningID, movieID, seats, pricePerSeat, holdTTL)
  Confirm() → []DomainEvent
  Release() → []DomainEvent
  Expire() → []DomainEvent    ← currently missing
```

**Repository Interface**
```go
type BookingRepository interface {
    Save(ctx, Booking) error
    Update(ctx, Booking) error
    FindByID(ctx, BookingID) (Booking, error)
    FindByReservationID(ctx, ReservationID) (Booking, error)
    FindByUserID(ctx, UserID, pagination Pagination) ([]Booking, int, error)
    FindByScreening(ctx, screeningID string) ([]Booking, error)
}
```

---

### 4.4 Identity Context _(Missing — To Be Added)_

**Purpose**: Manage who users are. Currently `userID` is an unvalidated string. This context must exist before authentication can be implemented.  
**Change rate**: Low.  
**Owner**: Platform / Auth team.

```
┌─────────────────────────────────────────────┐
│  IDENTITY CONTEXT  (proposed)               │
│                                             │
│  ┌──────────────────┐                      │
│  │  User             │ ← Aggregate Root    │
│  │  (Aggregate Root) │                     │
│  └────────┬──────────┘                     │
│           │                                │
│  ┌────────▼──────────┐                    │
│  │  UserID  (VO)      │                   │
│  │  Email   (VO)      │                   │
│  └────────────────────┘                   │
└─────────────────────────────────────────────┘
```

Minimum viable model for this project:
```go
type User struct {
    ID        UserID
    CreatedAt time.Time
}
type UserID struct { value string }  // typed wrapper around UUID
```

This is intentionally minimal. Full identity management (email, password, JWT) is a Phase 3+ concern.

---

### 4.5 Payment Context _(Placeholder — Simulated)_

**Purpose**: Process payment for a confirmed booking. Currently a no-op (clicking "Pay Now" directly calls confirm).

For the portfolio target, this context should exist as a stub with clear extension points:

```go
type Payment struct {
    ID          PaymentID
    BookingID   BookingID
    Amount      Money
    Status      PaymentStatus   // Pending, Succeeded, Failed, Refunded
    ProcessedAt *time.Time
}

// Domain Events
type PaymentSucceeded struct { PaymentID, BookingID, Amount }
type PaymentFailed    struct { PaymentID, BookingID, Reason string }
```

The confirm flow should be: `ReservationConfirmed` → Payment context initiates charge → `PaymentSucceeded` → `BookingConfirmed`.

---

## 5. Context Map

```
┌──────────────┐     read      ┌───────────────────┐
│   CATALOG    │◄──────────────│   RESERVATION     │
│   CONTEXT    │               │   CONTEXT         │
│              │  (screening   │                   │
│  Movie       │   price,      │  SeatReservation  │
│  Screening   │   layout)     │  (Redis-backed)   │
│  Screen      │               │                   │
└──────────────┘               └────────┬──────────┘
                                        │
                              domain event:
                              SeatsReserved,
                              ReservationConfirmed
                                        │
                               ┌────────▼──────────┐
                               │   BOOKING         │
                               │   CONTEXT         │
                               │                   │
                               │  Booking          │
                               │  (MongoDB-backed) │
                               └────────┬──────────┘
                                        │
                              domain event:
                              BookingConfirmed
                                        │
                               ┌────────▼──────────┐
                               │   PAYMENT         │
                               │   CONTEXT         │
                               │   (stub)          │
                               └───────────────────┘

┌──────────────┐
│   IDENTITY   │  ──── UserID flows into all contexts as a reference
│   CONTEXT    │        (anti-corruption layer: contexts don't share User entity)
└──────────────┘
```

**Integration patterns between contexts**:
| From | To | Pattern | Notes |
|---|---|---|---|
| Reservation → Booking | Domain Event (`SeatsReserved`) | Event-driven | Booking created when reservation confirmed |
| Reservation → Catalog | ACL query | Synchronous | Fetches screening price + layout to create reservation |
| Booking → Payment | Domain Event (`BookingConfirmed`) | Event-driven | Payment initiated after booking confirmed |
| All → Identity | Value reference | `UserID` VO | Contexts hold `UserID`, not the `User` entity |

---

## 6. Shared Kernel

Objects shared across contexts without translation:

| Object | Shared By | Justification |
|---|---|---|
| `Money` | Catalog, Booking, Payment | Fundamental financial VO |
| `UserID` | Reservation, Booking, Identity | Typed reference across contexts |
| `Pagination` | Booking | Query helper |

---

## 7. Ubiquitous Language Glossary

The language used in code should match the language used in the business. Current mismatches corrected here:

| Current Code Term | Domain Term | Reason |
|---|---|---|
| `Showtime` | **Screening** | A specific scheduled showing. "Showtime" is colloquial. |
| `Session` | **SeatReservation** | A time-bounded exclusive hold on specific seats |
| `Hall` | **Screen** | The physical room where a film is projected |
| `HoldRequest` | **ReserveSeatsCommand** | Command object, not a "request" |
| `SeatLockRepository` | **SeatReservationRepository** | Names the domain concept, not the mechanism |
| `HoldSeats` | **ReserveSeats** | "Hold" is implementation; "reserve" is the domain verb |
| `ConfirmBooking` | **ConfirmReservation** → then `CreateBooking` | Two separate operations in the target model |
| `ReleaseBooking` | **CancelReservation** | Releases the hold, not the booking |
| `GetSeatMap` | **GetScreeningAvailability** | More precise |
| `ExpiresAt int64` | `ExpiresAt time.Time` | Domain should work in time, not unix integers |

---

## 8. Domain Events (Target)

Events emitted by aggregates on state changes. Required for CQRS, audit trails, and decoupling contexts.

| Event | Emitted By | Payload | Consumers |
|---|---|---|---|
| `SeatsReserved` | `SeatReservation.Reserve()` | reservationID, screeningID, userID, seatIDs, expiresAt | Booking context (create held record) |
| `ReservationConfirmed` | `SeatReservation.Confirm()` | reservationID | Booking context (confirm record) |
| `ReservationReleased` | `SeatReservation.Release()` | reservationID | Booking context (mark released) |
| `ReservationExpired` | background job / TTL expiry | reservationID | Booking context (mark expired) |
| `BookingCreated` | `Booking.New()` | bookingID, reservationID, totalPrice | Analytics, notification |
| `BookingConfirmed` | `Booking.Confirm()` | bookingID, userID, totalPrice | Payment context, notification |
| `BookingCancelled` | `Booking.Release()` | bookingID | Analytics |
| `PaymentSucceeded` | `Payment.Process()` | paymentID, bookingID | Booking context (finalise) |
| `PaymentFailed` | `Payment.Process()` | paymentID, reason | Reservation context (release) |

---

## 9. Current vs. Target Model Delta

| Aspect | Current | Target |
|---|---|---|
| Bounded contexts | 2 (implicit) | 4 explicit + 1 stub |
| `Showtime` | Entity on Movie | Renamed `Screening`, same structure |
| `Session` | In domain/booking (wrong) | `SeatReservation` aggregate in Reservation context |
| `SeatStatus` | In domain/booking (wrong) | `SeatAvailability` DTO in interfaces layer |
| `User` | `string` | `UserID` VO in shared kernel, `User` AR in Identity context |
| Domain events | None | 9 events defined |
| `Booking.ID` | Assigned by service | Generated in `New()` constructor |
| `StatusExpired` | Never set | Set by `Expire()` method |
| Money panic | `panic()` | Returns `(Money, error)` |
| Hall overlap | Bypassed by service | Enforced via `Movie.AddScreening()` in service |

---

## 10. Domain Model Diagram (Target)

```
SHARED KERNEL
  Money(cents, currency)
  UserID(value)

CATALOG CONTEXT
  Movie [AR]
    id, title, genre[], rating, poster, description, durationMin
    owns: []Screening
    ─ AddScreening(s) → error            ← enforces hall overlap
    ─ RemoveScreening(id) → error
  Screening [Entity]
    id, movieID, screen, startTime, endTime, seatLayout, price
  SeatLayout [VO]
    rows, seatsPerRow
  Genre [VO]
    name

RESERVATION CONTEXT
  SeatReservation [AR]
    id(ReservationID), userID, screeningID, seats[], status, expiresAt
    ─ Reserve()  → []Event
    ─ Confirm()  → []Event
    ─ Release()  → []Event
    ─ Expire()   → []Event
  ReservedSeat [VO]
    id, row, number
  ReservationStatus [Enum]
    Pending | Confirmed | Released | Expired

BOOKING CONTEXT
  Booking [AR]
    id(BookingID), reservationID, userID, screeningID, movieID
    seats[], status, totalPrice, createdAt, expiresAt, confirmedAt
    ─ Confirm()  → []Event
    ─ Release()  → []Event
    ─ Expire()   → []Event
  BookedSeat [VO]  (same fields as ReservedSeat, separate type)
  BookingStatus [Enum]
    Held | Confirmed | Released | Expired

IDENTITY CONTEXT (stub)
  User [AR]
    id(UserID), createdAt

PAYMENT CONTEXT (stub)
  Payment [AR]
    id(PaymentID), bookingID, amount, status, processedAt
  PaymentStatus [Enum]
    Pending | Succeeded | Failed | Refunded
```
