# Database Design

_Phase 10 — Storage model, indexes, consistency — 2026-06-09_  
_Builds on: backend-analysis.md (Phase 0), domain-model.md (Phase 2), backend-refactor-plan.md (Phase 5)_

---

## 1. Two-Store Architecture

The system uses two databases with distinct responsibilities:

```
┌─────────────────────────────────────────────────────────────┐
│                       REDIS                                  │
│  Source of truth for real-time seat availability             │
│  Atomic multi-seat locking via Lua scripts                   │
│  TTL-based reservation expiry (10 min default)              │
│  Ephemeral: can be rebuilt from MongoDB confirmed state     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      MONGODB                                 │
│  Durable record of all bookings (financial source of truth) │
│  Movie and screening catalog                                 │
│  Queryable history for user booking lists                   │
│  Slow path: not on the critical seat-hold latency path      │
└─────────────────────────────────────────────────────────────┘
```

**Write ordering invariant**: Redis is written first, MongoDB second. If MongoDB fails after a successful Redis hold, the Redis TTL will eventually expire the hold. The inverse — MongoDB persisted but Redis not locked — would allow double-booking, so it is prevented by the compensation pattern in M1 Step 1.3.

---

## 2. Entity-Relationship Diagram

```
  MOVIE                          SCREENING
  ─────────────────────          ─────────────────────────────
  _id (PK)          ────────┐    _id (PK)
  title                      └──→ movie_id (FK)
  genres[]                        screen
  rating                          start_time
  duration_min                    end_time
  poster_url                      rows
  description                     seats_per_row
  created_at                      price_cents
                                  currency
                                  created_at
                                      │
                                      │ 1 : N
                                      ▼
                                  BOOKING
                                  ─────────────────────────────
                                  _id (PK)
                              ┌── screening_id (FK)
                              │   user_id (no FK — no users coll.)
                              │   seat_ids[]
                              │   status
                              │   total_price_cents
                              │   currency
                              │   held_at
                              │   expires_at     ← TTL index
                              │   confirmed_at
                              │   released_at
                              └── (screening_id, seat_ids are
                                   denormalized for display)
```

**No Users collection**: User identity is a UUID generated client-side. There is no authentication system or user profile store. `user_id` is a plain string field in `bookings`. If auth is added later, `user_id` becomes a foreign key into a `users` collection.

---

## 3. MongoDB Collection Schemas

### 3.1 `movies`

**Current BSON document** (as in source):
```json
{
  "_id":          "the-matrix",
  "title":        "The Matrix",
  "genres":       ["Action", "Sci-Fi"],
  "rating":       8.7,
  "duration_min": 136,
  "poster_url":   "https://...",
  "description":  "A computer hacker...",
  "showtimes":    [ { ...embedded showtime docs... } ],
  "created_at":   { "$date": "2026-01-01T00:00:00Z" }
}
```

**Problem (SM-09)**: Showtimes are embedded in the Movie document AND stored in a separate `showtimes` collection. Any write to a showtime must update both places or they diverge.

**Target BSON document**:
```json
{
  "_id":          "the-matrix",
  "title":        "The Matrix",
  "genres":       ["Action", "Sci-Fi"],
  "rating":       8.7,
  "duration_min": 136,
  "poster_url":   "https://...",
  "description":  "A computer hacker...",
  "created_at":   { "$date": "2026-01-01T00:00:00Z" }
}
```

The `showtimes` embedded array is **removed**. The `GET /movies/:id` handler queries the `screenings` collection for upcoming screenings and assembles the response at the application layer. This is a cheap secondary query (`movie_id` is indexed) and the extra network hop is acceptable given the read latency budget.

**Go struct (target)**:
```go
type MovieDocument struct {
    ID          string    `bson:"_id"`
    Title       string    `bson:"title"`
    Genres      []string  `bson:"genres"`
    Rating      float64   `bson:"rating"`
    DurationMin int       `bson:"duration_min"`
    PosterURL   string    `bson:"poster_url"`
    Description string    `bson:"description"`
    CreatedAt   time.Time `bson:"created_at"`
}
```

---

### 3.2 `screenings`

Renamed from `showtimes` to match ubiquitous language.

**Current BSON document**:
```json
{
  "_id":           "matrix-screen1-2026-06-10-18-00",
  "movie_id":      "the-matrix",
  "screen":        "Screen 1",
  "start_time":    { "$date": "2026-06-10T18:00:00Z" },
  "end_time":      { "$date": "2026-06-10T20:16:00Z" },
  "rows":          10,
  "seats_per_row": 12,
  "price": {
    "amount":   1200,
    "currency": "USD"
  },
  "created_at": { "$date": "2026-01-01T00:00:00Z" }
}
```

**Target BSON document** (Money flattened for simpler queries):
```json
{
  "_id":            "matrix-screen1-2026-06-10-18-00",
  "movie_id":       "the-matrix",
  "screen":         "Screen 1",
  "start_time":     { "$date": "2026-06-10T18:00:00Z" },
  "end_time":       { "$date": "2026-06-10T20:16:00Z" },
  "rows":           10,
  "seats_per_row":  12,
  "price_cents":    1200,
  "currency":       "USD",
  "created_at":     { "$date": "2026-01-01T00:00:00Z" }
}
```

**Why flatten Money**: The nested `price.amount` / `price.currency` requires an extra path component in every aggregation query. Two flat fields are simpler for range queries (`price_cents >= 1000`) and consistent with how the domain `Money` VO is serialized in DTOs.

**Go struct (target)**:
```go
type ScreeningDocument struct {
    ID          string    `bson:"_id"`
    MovieID     string    `bson:"movie_id"`
    Screen      string    `bson:"screen"`
    StartTime   time.Time `bson:"start_time"`
    EndTime     time.Time `bson:"end_time"`
    Rows        int       `bson:"rows"`
    SeatsPerRow int       `bson:"seats_per_row"`
    PriceCents  int64     `bson:"price_cents"`
    Currency    string    `bson:"currency"`
    CreatedAt   time.Time `bson:"created_at"`
}
```

---

### 3.3 `bookings`

**Current BSON document**:
```json
{
  "_id":         "bkg_9a1c4e2d",
  "showtime_id": "matrix-screen1-2026-06-10-18-00",
  "user_id":     "550e8400-e29b-41d4-a716-446655440000",
  "seat_ids":    ["A3", "A4"],
  "status":      "confirmed",
  "total_price": { "amount": 2400, "currency": "USD" },
  "held_at":     { "$date": "2026-06-09T12:00:00Z" },
  "expires_at":  { "$date": "2026-06-09T12:10:00Z" },
  "confirmed_at":{ "$date": "2026-06-09T12:03:14Z" }
}
```

**Target BSON document**:
```json
{
  "_id":           "bkg_9a1c4e2d",
  "reservation_id":"res_7f3e2a1b",
  "screening_id":  "matrix-screen1-2026-06-10-18-00",
  "user_id":       "550e8400-e29b-41d4-a716-446655440000",
  "seat_ids":      ["A3", "A4"],
  "status":        "confirmed",
  "total_cents":   2400,
  "currency":      "USD",
  "held_at":       { "$date": "2026-06-09T12:00:00Z" },
  "expires_at":    { "$date": "2026-06-09T12:10:00Z" },
  "confirmed_at":  { "$date": "2026-06-09T12:03:14Z" },
  "released_at":   null
}
```

**Changes**:
- `showtime_id` → `screening_id` (ubiquitous language)
- `reservation_id` added (cross-reference to Redis key)
- `total_price` object flattened to `total_cents` + `currency`
- `released_at` added explicitly (was absent in current model)

**Status enum**:

| Value | Description | `confirmed_at` | `released_at` | TTL index |
|---|---|---|---|---|
| `held` | Seat locked in Redis, not yet paid | null | null | Yes |
| `confirmed` | Payment accepted, permanent | set | null | No |
| `released` | User cancelled or TTL expired | null | set | No |

**Go struct (target)**:
```go
type BookingDocument struct {
    ID            string     `bson:"_id"`
    ReservationID string     `bson:"reservation_id"`
    ScreeningID   string     `bson:"screening_id"`
    UserID        string     `bson:"user_id"`
    SeatIDs       []string   `bson:"seat_ids"`
    Status        string     `bson:"status"`
    TotalCents    int64      `bson:"total_cents"`
    Currency      string     `bson:"currency"`
    HeldAt        time.Time  `bson:"held_at"`
    ExpiresAt     *time.Time `bson:"expires_at"`    // nil for confirmed
    ConfirmedAt   *time.Time `bson:"confirmed_at"`  // nil for held/released
    ReleasedAt    *time.Time `bson:"released_at"`   // nil for held/confirmed
}
```

---

## 4. Index Catalogue

### `movies`

```javascript
// Default PK
{ "_id": 1 }                              // unique, auto-created

// Sort by title (list endpoint default sort)
{ "title": 1 }

// Filter by genre (array field → multikey index)
{ "genres": 1 }

// Sort by rating descending
{ "rating": -1 }
```

Estimated collection size: 5 documents (seeded), < 1,000 in production. Indexes are for correctness and convention, not performance at this scale.

### `screenings`

```javascript
// Default PK
{ "_id": 1 }                              // unique, auto-created

// Get all screenings for a movie (most common query)
{ "movie_id": 1, "start_time": 1 }       // compound — covers both filter + sort

// Overlap detection: find screenings on same screen within a time window
// Query: { screen: X, $or: [ {start_time: {$lt: newEnd}}, {end_time: {$gt: newStart}} ] }
{ "screen": 1, "start_time": 1, "end_time": 1 }

// List upcoming screenings across all movies
{ "start_time": 1 }
```

**Overlap detection query** (used in `AddShowtime` domain invariant check):
```javascript
db.screenings.find({
  "screen": "Screen 1",
  "start_time": { "$lt": ISODate("2026-06-11T22:28:00Z") },
  "end_time":   { "$gt": ISODate("2026-06-11T20:00:00Z") }
})
// Uses: { screen: 1, start_time: 1, end_time: 1 }
```

### `bookings`

```javascript
// Default PK
{ "_id": 1 }                                    // unique

// User booking history — cursor pagination sorted by confirmed_at
{ "user_id": 1, "confirmed_at": -1 }            // compound, covers filter + sort
                                                 // partial: { status: "confirmed" }

// Screening audit: all bookings for a screening (admin view)
{ "screening_id": 1, "status": 1 }

// Cross-reference from reservation ID (confirm/release path)
{ "reservation_id": 1 }                         // unique

// TTL auto-cleanup: MongoDB deletes documents where expires_at < now()
// Only applied to held bookings (confirmed have expires_at: null)
{ "expires_at": 1 },  { expireAfterSeconds: 0 } // TTL index
```

**TTL Index behaviour**: MongoDB's TTL monitor runs every 60 seconds. A held booking with `expires_at: 2026-06-09T12:10:00Z` will be deleted between T+10:00 and T+11:00. Redis key expires exactly at T+10:00 (server-side TTL). The ±60s window means a MongoDB `held` record might briefly outlive its Redis lock — harmless because Redis is the availability source of truth.

**Partial index for user bookings** (reduces index size):
```javascript
db.bookings.createIndex(
  { "user_id": 1, "confirmed_at": -1 },
  { partialFilterExpression: { "status": "confirmed" } }
)
```

Only confirmed bookings are queried in booking history. This index is ~30% smaller than a full compound index.

---

## 5. Query Patterns

### Pattern Q-01: List upcoming screenings for a movie

```javascript
db.screenings.find(
  { "movie_id": "the-matrix", "start_time": { "$gte": now } },
  { projection: { "movie_id": 0 } }      // movie_id is redundant in context
).sort({ "start_time": 1 }).limit(20)
// Index used: { movie_id: 1, start_time: 1 }
// Estimated cost: O(log N + results)  ← covered index scan
```

### Pattern Q-02: User booking history (cursor pagination)

```javascript
// First page
db.bookings.find(
  { "user_id": "550e8400...", "status": "confirmed" }
).sort({ "confirmed_at": -1 }).limit(21)    // +1 to detect has_more

// Subsequent pages (cursor = last confirmed_at from previous page)
db.bookings.find(
  { "user_id": "550e8400...", "status": "confirmed",
    "confirmed_at": { "$lt": cursor } }
).sort({ "confirmed_at": -1 }).limit(21)
// Index used: partial { user_id: 1, confirmed_at: -1 } where status = "confirmed"
```

### Pattern Q-03: Screening overlap check

```javascript
db.screenings.find({
  "screen": "Screen 2",
  "start_time": { "$lt": proposedEnd },
  "end_time":   { "$gt": proposedStart }
}).limit(1)      // only need to know if any exist
// Index used: { screen: 1, start_time: 1, end_time: 1 }
```

### Pattern Q-04: Get booking by reservation ID (confirm path)

```javascript
db.bookings.findOne({ "reservation_id": "res_7f3e2a1b" })
// Index used: { reservation_id: 1 } (unique)
```

### Pattern Q-05: Cleanup of expired held bookings (TTL index)

MongoDB handles this automatically via the TTL index on `expires_at`. No application code needed. Rate: ~constant background work, not on any request path.

### Pattern Q-06: Admin — all bookings for a screening

```javascript
db.bookings.find(
  { "screening_id": "matrix-screen1-2026-06-10-18-00", "status": "confirmed" }
).sort({ "confirmed_at": 1 })
// Index used: { screening_id: 1, status: 1 }
```

---

## 6. Redis Data Model

### 6.1 Key Schema (Target)

```
seat:{screeningID}:{seatID}        STRING   reservationID      TTL=held_secs (no TTL = confirmed)
reservation:{reservationID}        STRING   JSON(Reservation)  TTL=held_secs (no TTL = confirmed)
idempotency:{key}                  STRING   JSON(CachedResp)   TTL=60s
ratelimit:{prefix}:{identifier}    STRING   counter            TTL=window_secs
```

**Renamed from current**:
- `seat:{showtimeID}:{seatID}` → `seat:{screeningID}:{seatID}` (domain rename)
- `session:{sessionID}` → `reservation:{reservationID}` (domain rename)

### 6.2 Reservation JSON Shape (stored in Redis)

```json
{
  "reservation_id": "res_7f3e2a1b",
  "screening_id":   "matrix-screen1-2026-06-10-18-00",
  "user_id":        "550e8400-e29b-41d4-a716-446655440000",
  "seat_ids":       ["A3", "A4"],
  "status":         "held",
  "held_at":        "2026-06-09T12:00:00Z",
  "expires_at":     "2026-06-09T12:10:00Z"
}
```

Status transitions: `held` → `confirmed` (PERSIST removes TTL) or → expired (TTL fires).

### 6.3 TTL Strategy

| Key | On Hold | On Confirm | On Release |
|---|---|---|---|
| `seat:{screeningID}:{seatID}` | `SET NX EX {hold_ttl_secs}` | `PERSIST` (remove TTL) | `DEL` |
| `reservation:{reservationID}` | `SET EX {hold_ttl_secs}` | `PERSIST` | `DEL` |

**Confirmed seats have no TTL** — this is correct for data integrity (a confirmed booking must persist until the screening ends). The cleanup of confirmed seat keys after the screening ends is handled by a background job (see §6.5).

### 6.4 Lua Script Inventory

Three Lua scripts are executed via `redis.NewScript` for atomicity:

#### `luaHold` — Atomic multi-seat lock

```lua
-- KEYS: seat keys to lock (e.g. KEYS[1] = "seat:screening1:A3")
-- ARGV[1]: reservationID
-- ARGV[2]: TTL in seconds
-- Returns: 0 = success, index of conflicting key on failure

local held = {}
for i, key in ipairs(KEYS) do
    local result = redis.call('SET', key, ARGV[1], 'NX', 'EX', ARGV[2])
    if result == false then
        -- Rollback: release all keys we already set
        for _, k in ipairs(held) do
            redis.call('DEL', k)
        end
        return i  -- return index of conflicting key
    end
    table.insert(held, key)
end
return 0
```

**All-or-nothing**: if any seat is taken, all previously locked keys are rolled back in the same Lua call. This is the core concurrency guarantee.

#### `luaConfirm` — Promote hold to confirmed

```lua
-- KEYS: seat keys + reservation key
-- ARGV[1]: reservationID (must match current value)
-- Returns: "OK" | "NOT_FOUND" | "WRONG_OWNER"

-- RC-02 fix: check reservation key exists before confirming seats
local resKey = KEYS[#KEYS]
local existing = redis.call('GET', resKey)
if existing == false then
    return "NOT_FOUND"  -- expired between checkout and confirm click
end
if existing ~= ARGV[1] then
    return "WRONG_OWNER"
end

-- Remove TTL from all seat keys (permanent)
for i = 1, #KEYS - 1 do
    redis.call('PERSIST', KEYS[i])
end
-- Remove TTL from reservation key
redis.call('PERSIST', resKey)
return "OK"
```

**RC-02 fix**: the `EXISTS` check at the start prevents the race where the TTL fires between the user clicking "Confirm" and this script executing.

#### `luaRelease` — Release hold

```lua
-- KEYS: seat keys + reservation key
-- ARGV[1]: reservationID
-- Returns: "OK" | "NOT_FOUND" | "ALREADY_CONFIRMED"

local resKey = KEYS[#KEYS]
local existing = redis.call('GET', resKey)
if existing == false then
    return "NOT_FOUND"  -- already expired or released — idempotent
end

-- RC-01 fix: don't release if already confirmed (no TTL means confirmed)
local ttl = redis.call('TTL', resKey)
if ttl == -1 then
    return "ALREADY_CONFIRMED"  -- PERSIST was called — seat is booked
end

-- Delete all seat keys and reservation key
for i = 1, #KEYS - 1 do
    redis.call('DEL', KEYS[i])
end
redis.call('DEL', resKey)
return "OK"
```

**RC-01 fix**: TTL == -1 means `PERSIST` was already called (i.e., `luaConfirm` ran). Refusing to delete a confirmed seat prevents the race between a late `Release` call and a `Confirm` that completed milliseconds earlier.

### 6.5 Confirmed-Seat Cleanup (TD-04 Fix)

Confirmed seats accumulate in Redis indefinitely — a memory leak for high-volume deployments. A cleanup job runs after each screening ends:

```go
// Called by a background goroutine / cron job
func (r *SeatLockRepository) CleanupExpiredScreening(ctx context.Context, screeningID string, endTime time.Time) error {
    if time.Now().Before(endTime) {
        return nil // screening not over yet — RC-03 fix
    }

    // Scan for all seat keys for this screening (SCAN, not KEYS — non-blocking)
    pattern := fmt.Sprintf("seat:%s:*", screeningID)
    iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()
    var keys []string
    for iter.Next(ctx) {
        keys = append(keys, iter.Val())
    }
    if err := iter.Err(); err != nil {
        return err
    }
    if len(keys) == 0 {
        return nil
    }

    // Pipeline DEL for all confirmed seats
    pipe := r.client.Pipeline()
    for _, key := range keys {
        pipe.Del(ctx, key)
    }
    _, err := pipe.Exec(ctx)
    return err
}
```

**RC-03 fix**: only delete keys where the screening's `end_time < now()`. A previous bug would delete keys for any past screening without checking whether the end time had actually passed — this risked deleting held seats during an active screening if the cleanup timer fired early.

### 6.6 N+1 Fix: Pipeline in GetSeatStatuses

Current implementation issues one GET + one TTL per seat = 2 × N round trips. For a 10×12 hall: 240 Redis operations.

**Target implementation** (M6 Step 6.2):

```go
func (r *SeatLockRepository) GetSeatStatuses(ctx context.Context, screeningID string, userID string, allSeatIDs []string) (map[string]domain.SeatStatus, error) {
    pipe := r.client.Pipeline()
    getCmds := make([]*redis.StringCmd, len(allSeatIDs))
    ttlCmds := make([]*redis.DurationCmd, len(allSeatIDs))

    for i, seatID := range allSeatIDs {
        key := fmt.Sprintf("seat:%s:%s", screeningID, seatID)
        getCmds[i] = pipe.Get(ctx, key)
        ttlCmds[i] = pipe.TTL(ctx, key)
    }
    _, err := pipe.Exec(ctx)
    // redis.Nil errors on GET are expected for available seats — ignore at individual cmd level

    statuses := make(map[string]domain.SeatStatus, len(allSeatIDs))
    for i, seatID := range allSeatIDs {
        val, getErr := getCmds[i].Result()
        ttl, _      := ttlCmds[i].Result()

        if errors.Is(getErr, redis.Nil) {
            statuses[seatID] = domain.SeatStatusAvailable
            continue
        }
        if getErr != nil {
            return nil, getErr
        }

        switch {
        case ttl == -1:
            statuses[seatID] = domain.SeatStatusConfirmed
        case val == userID:
            statuses[seatID] = domain.SeatStatusMine
        default:
            statuses[seatID] = domain.SeatStatusHeld
        }
    }
    return statuses, err
}
```

**Performance improvement**: 240 serial round trips → 1 pipeline round trip. At 270 concurrent viewers (scale ceiling), this reduces Redis command rate from ~64,800/min to 270/min for seat map polling.

---

## 7. Redis Cluster Compatibility

### Hash Tag Requirement

Lua scripts that operate on multiple keys require all keys to be in the same hash slot. Redis Cluster assigns slots based on the hash of the key name (or hash tag if `{...}` is present).

**Current key format**: `seat:{showtimeID}:{seatID}`  
In Redis Cluster, the hash is computed on the full key: `seat:matrix-screen1-2026-06-10-18-00:A3`.

In the Lua `luaHold` script, all KEYS are seat keys for the same screening. Their hash must match.

**With hash tags**: Redis Cluster hashes only the content inside the first `{...}` pair:
```
seat:{matrix-screen1-2026-06-10-18-00}:A3
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      hash slot determined by this portion only
```

All seats for `matrix-screen1-2026-06-10-18-00` hash to the same slot → the Lua script is valid in Cluster mode.

**Required key format for Cluster**:
```
seat:{screeningID}:{seatID}                ← { } around screeningID only
reservation:{reservationID}                ← no multi-key scripts — any slot OK
```

**Note**: the `reservation:` key is only accessed by single-key GET/SET/DEL commands, never in a multi-key script. It does NOT need to be co-located with seat keys.

### Single-Node vs Cluster

| Deployment | Key format | Comment |
|---|---|---|
| Single Redis / Sentinel | `seat:{screeningID}:{seatID}` | Works as-is (no slot routing) |
| Redis Cluster | `seat:{screeningID}:{seatID}` | Hash tag on screeningID → same slot |

The key format `seat:{screeningID}:{seatID}` works in both modes. Use this format from Phase 5 M7 onward.

---

## 8. Data Consistency Model

### Write Ordering (Hold Path)

```
Client
  │
  ▼
BookingService.ReserveSeats()
  ├─1. Execute luaHold in Redis  ←── atomic, fast (<1ms)
  │    If fails → return 409 SEATS_UNAVAILABLE
  │
  ├─2. Write Booking(status=held) to MongoDB
  │    If fails → COMPENSATE: execute luaRelease in Redis
  │               Return 500 INTERNAL_ERROR
  │
  └─3. Return Reservation to handler
```

### Write Ordering (Confirm Path)

```
Client
  │
  ▼
BookingService.ConfirmReservation()
  ├─1. Execute luaConfirm in Redis  ←── atomic
  │    If "NOT_FOUND" → return 404
  │    If "ALREADY_CONFIRMED" → return 409
  │
  ├─2. Update Booking(status=confirmed, confirmed_at=now) in MongoDB
  │    If fails → COMPENSATE: execute luaRelease in Redis
  │               This unconfirms the seat (seat goes back to available)
  │               Return 500 INTERNAL_ERROR to client
  │               Client must retry confirm
  │
  └─3. Return Booking to handler
```

### Consistency Guarantees

| Scenario | Outcome | Consistency |
|---|---|---|
| Redis hold succeeds, MongoDB write fails | Compensated: Redis released | ✅ No phantom hold |
| Redis confirm succeeds, MongoDB update fails | Compensated: Redis released | ⚠️ User must retry confirm |
| Redis release succeeds, MongoDB update fails | Seat freed, booking stuck in `held` status | ⚠️ TTL index cleans MongoDB in ≤60s |
| Redis down, MongoDB up | Hold fails fast (Redis unavailable) | ✅ No partial state |
| MongoDB down, Redis up | Hold succeeds in Redis, MongoDB compensation fails | ⚠️ Redis holds memory until TTL |

The most painful failure mode is the third row: the booking MongoDB document stays `held` after Redis is released, for up to 60 seconds until the TTL index fires. This is acceptable for a booking system — the seat is freed immediately (Redis), and the stale MongoDB document self-heals.

### Redis as Cache vs. Source of Truth

Redis is **not** a cache for this system. It is the **primary source of truth for seat availability**. The MongoDB `bookings` collection is the **durable record** but is always queried after Redis for availability.

Redis can be rebuilt from MongoDB: query all confirmed bookings for a screening, re-lock their seats in Redis with no TTL. This rebuild is the disaster-recovery path (Redis data loss scenario).

```go
func (s *BookingService) RebuildSeatLocks(ctx context.Context, screeningID string) error {
    bookings, err := s.bookingRepo.FindConfirmedByScreening(ctx, screeningID)
    if err != nil { return err }
    for _, b := range bookings {
        // Re-lock with PERSIST (no TTL — already confirmed)
        if err := s.seatLockRepo.LockConfirmed(ctx, screeningID, b.SeatIDs, b.ID); err != nil {
            return err
        }
    }
    return nil
}
```

---

## 9. Volume Estimates

### Per Screening (10×12 hall = 120 seats)

| Metric | Value |
|---|---|
| Redis seat keys | 120 |
| Redis memory per seat key | ~80 bytes (key + reservationID value) |
| Redis memory per reservation | ~300 bytes (JSON) |
| Total Redis memory at full occupancy | ~120 × 80 + 120 × 300 = ~46 KB |
| MongoDB booking documents per screening | 1–120 |
| MongoDB booking document size | ~500 bytes |
| MongoDB storage per full screening | ~60 KB |

### Per Day (10 screenings, 50% occupancy)

| Metric | Value |
|---|---|
| New booking documents | 10 × 60 = 600 |
| Redis peak memory (all screenings live simultaneously) | ~460 KB |
| MongoDB cumulative bookings after 1 year | ~219,000 documents |
| MongoDB storage after 1 year (bookings only) | ~107 MB |
| MongoDB storage after 1 year (total) | <1 GB |

At this scale, storage is not a concern. Indexes are the dominant MongoDB concern (they must fit in RAM for good query performance). The full index set for all three collections is estimated at <10 MB.

### Redis Memory Budget

```
Active screenings simultaneously: ~10 (typical cinema schedule)
Seats per screening: 120
Redis memory per active screening: ~46 KB
Total Redis memory for all active screenings: ~460 KB

Reservation objects (at 100 concurrent holds): 100 × 300 = 30 KB

Rate limit counters: ~10,000 × 50 bytes = 500 KB

Total estimated Redis memory: < 2 MB
```

Redis is memory-efficient for this workload. A single `redis.io` instance with 128 MB is vastly over-provisioned. Scale concern is throughput (commands/sec), not memory.

---

## 10. Index Migration Plan

Indexes should be created in the background (`createIndex` with `background: true` in the Go driver, or the MongoDB Shell equivalent) to avoid locking the collection during creation.

### Immediate (M1 — no schema changes needed)

```go
// bookings: TTL index to auto-delete expired holds (fixes TD-04)
indexModel := mongo.IndexModel{
    Keys: bson.D{{"expires_at", 1}},
    Options: options.Index().
        SetExpireAfterSeconds(0).
        SetSparse(true).  // only index documents where expires_at exists (confirmed have nil)
        SetName("expires_at_ttl"),
}
```

```go
// bookings: reservation_id lookup
mongo.IndexModel{
    Keys: bson.D{{"reservation_id", 1}},
    Options: options.Index().SetUnique(true).SetSparse(true).SetName("reservation_id_unique"),
}
```

### Phase 5 M4 (collection rename: showtimes → screenings)

```go
// Step 1: create screenings collection with correct indexes
// Step 2: copy showtimes → screenings (migration script)
// Step 3: update all application code to use screenings
// Step 4: drop showtimes collection after verification
```

### Phase 5 M7 (schema changes: flatten Money, remove embedded showtimes from movies)

```go
// movies: remove showtimes array
// Update via: db.movies.updateMany({}, { $unset: { showtimes: "" } })

// bookings: rename showtime_id → screening_id, total_price → total_cents + currency
// These are additive renames — add new field, backfill, then remove old field
// Step 1: db.bookings.updateMany({}, { $rename: { "showtime_id": "screening_id" } })
// Step 2: db.bookings.updateMany({}, [{
//   $set: {
//     total_cents: "$total_price.amount",
//     currency: "$total_price.currency"
//   }
// }])
// Step 3: db.bookings.updateMany({}, { $unset: { "total_price": "" } })
```

All migration scripts should be run via the seeder package or a dedicated `migrate` command, not manually in the shell.

---

## 11. Current Database Issues (Cross-reference)

| Issue | Location | Severity | Fix Reference |
|---|---|---|---|
| Fire-and-forget MongoDB save after Redis hold | `application/booking/service.go` | Critical | M1 Step 1.3 — compensation on failure |
| No TTL index on `bookings.expires_at` | MongoDB | High | M1 — immediate index creation |
| Confirmed seats never cleaned from Redis | Redis | High | M6 Step 6.3 — cleanup job |
| Showtimes embedded in Movie + separate collection | MongoDB | Medium | M4/M7 — remove embedded array |
| N+1 Redis calls in GetSeatStatuses | Redis | High | M6 Step 6.2 — pipeline |
| No `reservation_id` field in bookings | MongoDB | Medium | M3 Step 3.1 — add field |
| `total_price` nested object | MongoDB | Low | M7 Step 7.1 — flatten to cents |
| `showtime_id` field name | MongoDB | Low | M7 — rename to `screening_id` |
| No Redis Cluster hash tags | Redis keys | Medium | M7 Step 7.2 — add `{screeningID}` tag |
| `session:{id}` key prefix | Redis | Low | M7 — rename to `reservation:{id}` |
