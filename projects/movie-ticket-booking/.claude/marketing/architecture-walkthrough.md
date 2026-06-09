# Architecture Walkthrough

_A scripted narrative for presenting this project to a technical audience — colleagues, interviewers, or a code review panel. Runs 20–30 minutes with questions. Each section has talking points and transition cues._

---

## Opening (2 min)

**Goal**: Frame the project and set up the problem that everything else is a response to.

---

"I'm going to walk through the Cinema Booking Engine — a full-stack seat reservation system. But I want to start with the problem, not the solution, because the architecture is a direct response to a specific correctness challenge.

Here's the problem: two users click the same seat at the same time. Most booking systems handle this incorrectly. They check if the seat is available, then book it — two separate operations. Between those two operations, another user can complete the same sequence. Both users get a confirmation. One seat, two bookings.

Everything we'll look at today is shaped by the requirement to make that impossible. Let me show you how."

**Transition**: "Let's start with the system at a high level."

---

## System Overview (3 min)

**Goal**: Show the major components and their roles before going deep.

---

Draw or point to:
```
Next.js 15              Go + Gin API             Redis 7
(frontend)    ────────►  (backend)    ─────────►  (seat locks)
                              │
                              └──────────────────► MongoDB 7
                                                   (bookings, movies)
```

"The system has three concerns with different characteristics:

**Real-time availability** — every connected user sees seat status update every two seconds. This is high-frequency, ephemeral, and latency-sensitive. Redis is the right store.

**Durable booking records** — confirmed bookings need to survive restarts, be queryable by user, and support analytics. MongoDB is the right store.

**Interactive UI** — seat selection has a state machine: browsing → holding → checkout → confirmed. Next.js with TanStack Query handles this without global state management.

The interesting design decision is that Redis and MongoDB are not redundant — they're authoritative for different things. Redis is the source of truth for *current* seat availability. MongoDB is the source of truth for *confirmed* bookings."

**Transition**: "Now let's look at how the Go backend is structured."

---

## Clean Architecture Layers (5 min)

**Goal**: Show the dependency rule and why it matters in practice.

---

"The backend follows Clean Architecture with four layers. The crucial rule: dependencies only point inward. Nothing in the domain layer imports anything external."

```
interfaces/http  →  application  →  domain  ←  infrastructure
(Gin handlers)      (use cases)    (entities)   (Redis, MongoDB)
```

"Let me make this concrete. The `domain/booking` package contains the `Booking` aggregate. It has no imports from Gin, Redis, MongoDB, or even UUID libraries. When I call `booking.Confirm()`, I get either `nil` or `ErrAlreadyConfirmed`. No database query. No network call. Pure Go.

This means I can unit test every business rule in milliseconds without starting any infrastructure. And when I want to swap MongoDB for PostgreSQL, I write a new repository implementation in the infrastructure layer and nothing else changes.

We enforce this with a CI assertion:"

```bash
grep -r '"github.com/' backend/internal/domain/ && exit 1 || true
```

"If the domain layer ever imports an external package, the build fails. The pattern only has teeth when it's automated."

**Show**: Point to the domain package. Show the absence of `import` blocks with external packages.

**Transition**: "Let's look at the bounded contexts — how the domain is carved up."

---

## Domain-Driven Design (5 min)

**Goal**: Show bounded context thinking, not just folder organisation.

---

"I identified five bounded contexts in this domain:

```
Catalog          Reservation       Booking
(movies,         (seat locks,      (durable
 screenings)      TTL holds)        records)

Identity (future)           Payment (future)
```

Each context has its own ubiquitous language. The word 'seat' means something different in each:
- In Catalog: a seat is a position in a layout (row + number)
- In Reservation: a seat is a Redis key with a TTL
- In Booking: a seat is an item in a confirmed purchase record

These contexts don't share types. When Reservation needs movie data from Catalog, it reads via an Anti-Corruption Layer that returns primitives — screening ID, price in cents — not domain objects. This prevents the Catalog model from leaking into the Reservation context."

**Show the `Booking` aggregate**:

"Let's look at the aggregate. The `Booking` struct has a state machine enforced at the method level. `Confirm()` transitions `held → confirmed`. Calling `Confirm()` on an already-confirmed booking returns `ErrAlreadyConfirmed`. Calling `Release()` on a confirmed booking returns `ErrAlreadyConfirmed`. Invalid states are impossible to create."

"There's also the PopEvents() pattern. After `Confirm()` runs, the aggregate holds a `BookingConfirmedEvent` in an internal slice. The application service collects it and dispatches it to the event handlers — currently a synchronous in-process dispatcher, replaceable with NATS JetStream without changing any domain or application code."

**Transition**: "Now the most interesting part — how we actually lock the seats."

---

## The Concurrency Challenge (8 min)

**Goal**: This is the centrepiece. Walk through the problem, the solution, and the edge cases.

---

"Let me show you the core correctness problem."

```
User A: READ A1=available, READ A2=available ──── WRITE A1=booked, A2=booked ✓
User B: READ A1=available, READ A2=available ── WRITE A1=booked, A2=booked ✓
                                                  ↑ double-booking
```

"Any read-then-write pattern has this window. The solution must be atomic."

**The Lua script:**

"Redis Lua scripts run atomically — the entire script executes as a single command from Redis's perspective. No other command can interleave. This gives us a place to do atomic multi-seat locking.

The script attempts to set each seat key with `SET NX` — only if it doesn't exist. If any seat is already taken, it deletes all previously set keys in the same execution. Rollback is part of the script."

```lua
local held = {}
for i, key in ipairs(KEYS) do
    if redis.call('SET', key, ARGV[1], 'NX', 'EX', ARGV[2]) == false then
        for _, k in ipairs(held) do redis.call('DEL', k) end  -- rollback
        return i  -- which seat conflicted
    end
    table.insert(held, key)
end
return 0  -- all seats locked
```

"The TTL (`EX`) means unreleased holds automatically expire. No orphaned locks."

**The three race conditions:**

"Getting the happy path right took a day. Finding the edge cases took another week.

**RC-01**: Confirm and release arrive simultaneously. The release script calls DEL. But if confirm already ran and called PERSIST, the key has no TTL — TTL returns -1. The release script checks this: if TTL is -1, the seat is confirmed, don't delete.

**RC-02**: The user's 10-minute hold expires between when they load the checkout page and when they click Confirm. The confirm script calls PERSIST. PERSIST on a non-existent key returns 0 — not an error — so the script thinks it succeeded. Fixed by adding an EXISTS check at the start of the confirm script.

**RC-03**: The cleanup job deletes confirmed seat keys after a screening ends, to prevent Redis memory accumulating. If the clock comparison is off, it fires while the screening is running. Fixed by passing the screening's end_time to the cleanup function and returning immediately if `now() < end_time`."

**The proof:**

"I verified the basic guarantee with 10,000 goroutines:"

```go
const goroutines = 10_000
var wins atomic.Int32
// ... all 10,000 goroutines try to hold the same seat
require.Equal(t, int32(1), wins.Load())
```

"This uses a real Redis instance via testcontainers — not a mock — and runs under the Go race detector."

**Transition**: "Let's look at the observability layer."

---

## Observability (3 min)

**Goal**: Show production thinking, not just functionality.

---

"The system is wired end-to-end for observability. A single booking request produces three signals that are all correlated by trace ID:

A Prometheus histogram data point with an exemplar — a data point that carries a trace ID. When the P99 latency spikes in Grafana, you click the exemplar dot to jump directly to that specific slow request in Tempo.

A Tempo trace showing the span waterfall: HTTP handler → service → Redis Lua execution → MongoDB insert. You can see exactly where the 15ms of a 100ms request is spent.

A Loki log line with the trace ID embedded. From the Tempo trace, you click to jump to the exact log lines for that request.

One click from a metric anomaly to the specific request that caused it."

**Show the SLOs:**

"We have three SLOs with alerting: API availability 99.9%, seat hold P99 under 100ms, confirmation success rate over 99%. The 100ms SLO shaped the architecture — it's why we chose Redis (2ms) over MongoDB transactions (20ms) for the locking layer."

**Transition**: "Let me show you what I'd change if I were doing this again."

---

## Known Issues and Roadmap (2 min)

**Goal**: Show honest self-assessment. This is often what separates senior from junior candidates.

---

"There are three known issues I'd fix before calling this production-ready.

First, the MongoDB write after a Redis hold is currently fire-and-forget. If MongoDB is unavailable, the Redis lock exists but there's no booking record. The fix is a compensating transaction — if the MongoDB write fails, release the Redis lock. It's documented and in the refactor plan; I just haven't implemented it yet.

Second, admin credentials are hardcoded as `admin:admin` in the source. They need to come from environment variables. This is a 30-minute fix that I've deliberately left in the codebase to demonstrate honest assessment — the architecture documents include it as the top priority security finding.

Third, the domain model still has `Showtime` and `Session` as names when the DDD analysis determined they should be `Screening` and `SeatReservation`. The naming is inconsistent, which makes the code harder to reason about."

"The 32-item technical debt register and the 24-step refactor plan in `.claude/` document all of this and prioritise it. Knowing what's wrong and in what order to fix it is a different skill from writing the code — and I think it's the more important one."

---

## Q&A Preparation

**"Why not use a single relational database for everything?"**

> "A relational database could handle everything, but the seat polling pattern creates a specific problem: the seat map is read 540 times a second (270 viewers × 2 polls), and writes (holds) need to be atomic. With a relational DB, those reads and writes contend at the row level. Redis keeps them completely independent — reads go to Redis keys, writes go through the Lua script. The cost is operational complexity and eventual consistency between Redis and MongoDB."

**"How does this scale beyond one API server?"**

> "The API servers are stateless — they all point to the same Redis and MongoDB. Scaling is horizontal. The only constraint is the Redis key schema: for Redis Cluster, I need hash tags so that all seat keys for a screening land in the same slot (required for multi-key Lua scripts). The key format `seat:{screeningID}:{seatID}` handles this — Redis hashes on the `{screeningID}` portion."

**"What happens if two instances run the cleanup job at the same time?"**

> "The cleanup job scans `seat:{screeningID}:*` keys and deletes them. If two instances run this simultaneously, they both scan the same keys and both attempt to delete them. Redis DEL on a non-existent key returns 0 (not an error) — it's idempotent. Worst case: the second instance does some unnecessary work. No correctness issue."

**"Why not use an ORM for MongoDB?"**

> "The domain aggregates would need to be coupled to the ORM's base types or annotations, which violates the dependency rule (domain importing infrastructure). Instead, infrastructure-level `MovieDocument` and `BookingDocument` structs hold the BSON annotations. The repository maps between them and the domain types. It's more code, but the domain stays clean."

**"What's the hardest thing you'd have to change to go multi-tenant?"**

> "The booking model has no concept of a cinema chain or tenant. `screening_id` is a global identifier. To go multi-tenant, I'd add a `tenant_id` to every document and Redis key, update all queries to filter by tenant, and probably split MongoDB into per-tenant databases. The domain model would need a `TenantID` value object in the shared kernel. The bounded contexts are already clean enough that this change would be mostly mechanical — it wouldn't require redesigning the aggregates."
