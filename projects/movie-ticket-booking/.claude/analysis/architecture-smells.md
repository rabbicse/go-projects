# Architecture Smells

_Identified from full source read — 2026-06-08_

Severity: 🔴 High (blocks production use) | 🟡 Medium (degrades maintainability) | 🟢 Low (polish/preference)

---

## Backend

### 🔴 SM-01: Hardcoded LAN IP Addresses in Config Defaults

**Location**: `backend/internal/config/config.go:28-29`
```go
Addr:  string `env:"REDIS_ADDR"  envDefault:"192.168.0.50:6379"`
URI:   string `env:"MONGODB_URI" envDefault:"mongodb://192.168.0.50:27017"`
```
**Problem**: These are the developer's home network IPs. A fresh clone fails immediately without a `.env` file, and the error is cryptic.
**Fix**: Change defaults to `localhost:6379` and `mongodb://localhost:27017`.

### 🔴 SM-02: Hardcoded Admin Credentials

**Location**: `backend/internal/interfaces/http/router.go:57`
```go
admin := api.Group("/admin", gin.BasicAuth(gin.Accounts{"admin": "admin"}))
```
**Problem**: Credentials are in source code. `admin:admin` is trivially guessable. No way to rotate without a redeploy.
**Fix**: Read from env vars `ADMIN_USER` / `ADMIN_PASSWORD`.

### 🔴 SM-03: MongoDB Save Failure Silently Succeeds the Hold

**Location**: `backend/internal/application/booking/service.go:85-88`
**Problem**: If MongoDB is unavailable, `HoldSeats` still returns a valid session. On confirm, `FindBySessionID` returns `ErrBookingNotFound` → user gets a 500 on a confirmed-looking flow. Seats are locked in Redis with no MongoDB record.
**Fix**: Return error if MongoDB save fails; release the Redis hold as a compensating action.

### 🟡 SM-04: `Session` Struct in Domain Package

**Location**: `backend/internal/domain/booking/repository.go:44-54`
**Problem**: `Session` represents ephemeral Redis state (TTL, unix timestamp). It is not a domain concept — it's an infrastructure artifact. The domain `Repository` interface returns `Session`, coupling the domain to Redis semantics.
**Fix**: Move `Session` to infrastructure/redis, or model it as a proper domain concept (`HoldSession`) with domain semantics (not unix timestamps).

### 🟡 SM-05: Domain `SeatStatus` Carries HTTP Presentation Fields

**Location**: `backend/internal/domain/booking/seat.go:33-38`
```go
type SeatStatus struct {
    HeldByMe  bool   `json:"held_by_me"`
    ExpiresAt *int64 `json:"expires_at,omitempty"`
}
```
**Problem**: `json:` struct tags and unix timestamp encoding are HTTP/API concerns, not domain concerns. The domain shouldn't know about JSON or seconds-since-epoch.
**Fix**: Define a `SeatStatusView` DTO in the interfaces layer. Domain returns a plain `SeatAvailability` struct.

### 🟡 SM-06: `CreateShowtime` Bypasses Domain Invariant

**Location**: `backend/internal/application/movie/service.go:49-56`
**Problem**: `CreateShowtime` calls `repo.SaveShowtime()` directly. The domain's `Movie.AddShowtime()` method validates hall overlap — this check is bypassed. Two conflicting showtimes can be created for the same hall.
**Fix**: Load the `Movie` aggregate, call `m.AddShowtime(st)`, then persist.

### 🟡 SM-07: `BookingService.ShowtimePrice` is a Query on the Wrong Service

**Location**: `backend/internal/application/booking/service.go:164-170`
**Problem**: `ShowtimePrice` reads movie/showtime data but lives in `BookingService`, which depends on `movie.Repository`. This creates an unnecessary cross-domain dependency.
**Fix**: Remove from BookingService. The handler can call `MovieService.GetShowtime()` if it needs price.

### 🟡 SM-08: `maxSeats` Validated Twice

**Location**: `BookingHandler.HoldSeats` and `BookingService.HoldSeats`
**Problem**: Both handler and service check `len(req.SeatIDs) > h.maxSeats`. The handler check fires first, making the service check redundant — but if the handler check is ever removed, the service check remains a hidden guard with no test.
**Fix**: Keep validation in service only. Handler should not replicate business rules.

### 🟡 SM-09: No Domain Events

**Problem**: Status transitions (`Held → Confirmed`, `Held → Released`) are silent. There is no way to add side effects (email, analytics, audit log) without modifying `BookingService`.
**Fix**: Emit domain events from aggregate methods; collect in service; publish to in-process event bus or channel.

### 🟡 SM-10: `Booking.ID` Assigned Outside the Aggregate

**Location**: `backend/internal/application/booking/service.go:83`
```go
b.ID = uuid.New().String()
```
**Problem**: Identity is assigned by the service, not by the aggregate. The aggregate's `New()` constructor returns a `Booking` with an empty `ID`.
**Fix**: Generate UUID inside `booking.New()`.

### 🟢 SM-11: `Money.Add` Panics Instead of Returns Error

**Location**: `backend/internal/domain/shared/money.go:22`
```go
func (m Money) Add(other Money) Money {
    if m.currency != other.currency {
        panic("cannot add money of different currencies")
    }
```
**Problem**: A panic in domain logic can crash the server if unrecovered. Currently only `gin.Recovery()` saves it.
**Fix**: Return `(Money, error)`.

### 🟢 SM-12: `StatusExpired` Never Set

**Location**: `backend/internal/domain/booking/booking.go:17`
**Problem**: `StatusExpired` is declared but never assigned. Expired bookings remain as `StatusHeld` in MongoDB. Queries filtering on `status = expired` return nothing.
**Fix**: Add an `Expire()` method to `Booking` and call it from a background job or at query time.

### 🟢 SM-13: Seeder Uses External TMDB Image URLs

**Location**: `backend/internal/infrastructure/seeder/seeder.go`
**Problem**: PosterURLs point to `image.tmdb.org`. These break in air-gapped environments, change when TMDB updates paths, and create a runtime external dependency just to run tests.
**Fix**: Use local placeholder images or configurable URL prefix.

---

## Frontend

### 🔴 SM-14: Admin Auth in `localStorage` (Frontend)

**Location**: `frontend/src/app/admin/login/page.tsx`
**Problem**: Admin credentials are stored in `localStorage`. XSS reads them trivially. There is no server-side session.
**Fix**: Use httpOnly cookies or a proper session mechanism.

### 🟡 SM-15: `ShowtimePage` is a 436-Line God Component

**Location**: `frontend/src/app/showtimes/[showtimeId]/page.tsx`
**Problem**: A single component manages data fetching, booking state machine, multiple timers, UI layout, and inline UI primitives. It is impossible to unit test any part of it in isolation.
**Fix**: Extract `useBookingFlow` hook, `useCountdown` hook; split into `SeatSelectionPanel`, `CheckoutPanel`, `PaymentPanel`, `ConfirmationPanel`.

### 🟡 SM-16: Unconditional 2-Second Polling

**Location**: `frontend/src/components/SeatGrid.tsx:40`
```typescript
intervalRef.current = setInterval(fetchStatuses, 2000);
```
**Problem**: Polls even when no user interaction is happening. Creates ~500 requests/minute per open tab at scale. No pause on error, no visibility API integration (polls even when tab is hidden).
**Fix**: Use `document.visibilityState` to pause when hidden; implement exponential back-off on error; consider WebSocket or SSE for real-time updates.

### 🟢 SM-17: User Identity Lost on Tab Refresh

**Location**: `frontend/src/app/showtimes/[showtimeId]/page.tsx:11-19`
**Problem**: `sessionStorage` clears on tab close. A user who has held seats and refreshes the page gets a new user ID and can no longer confirm or release their session. The held seats are orphaned until TTL expiry.
**Fix**: Use `localStorage` for user identity (persists across sessions); or implement proper authentication.

### 🟢 SM-18: `PAYMENT_TTL_S` Magic Number

**Location**: `frontend/src/app/showtimes/[showtimeId]/page.tsx:9`
```typescript
const PAYMENT_TTL_S = 180;
```
**Problem**: Not configurable, not documented, not aligned with any backend setting. If `HOLD_TTL` is reduced below 3 minutes, the payment timer outlasts the hold.
**Fix**: Derive from backend session `expires_at`, or make it a `NEXT_PUBLIC_PAYMENT_TTL` env var.
