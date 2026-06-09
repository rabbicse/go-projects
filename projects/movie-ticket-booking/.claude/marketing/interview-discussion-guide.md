# Interview Discussion Guide

_How to talk about this project in technical interviews — from recruiter screens to principal engineer panels._

---

## The 30-Second Elevator Pitch

For a recruiter phone screen or an opening "tell me about yourself":

> "I built a full-stack cinema booking system in Go and Next.js, but the interesting part is the concurrency. Two users clicking the same seat simultaneously is a race condition that most booking systems handle incorrectly. I solved it with a Redis Lua script that locks all requested seats atomically — all-or-nothing — and then spent time finding the subtler races: what happens when a hold expires at the exact moment someone confirms, or when a release and confirm arrive concurrently. It's documented, tested under 10,000 concurrent goroutines, and sits inside a clean DDD architecture."

**Why this works**: leads with the hard problem, not the tech stack. Engineers who hear this want to ask a follow-up question.

---

## The 5-Minute Technical Summary

For a hiring manager or engineering manager who asks "walk me through what you built":

**Structure: Problem → Design → Interesting parts → What I'd change**

> "The system lets users browse movies, select seats in real time, hold them for 10 minutes, and confirm a booking. The interesting engineering is in the seat locking.
>
> The naive approach — read availability, then write booking — has a race window. Two users can both see a seat as available and both successfully book it. The fix needs to be atomic.
>
> I chose Redis for the locking layer for two reasons: first, Redis Lua scripts run atomically on the server, so I can lock multiple seats in one script execution with rollback if any conflict. Second, the seat map is polled every 2 seconds by every connected client, so I needed reads to be completely independent from writes — which you don't get with database-level row locks.
>
> The tricky part wasn't the happy path. It was the edge cases: what if the TTL expires between checkout and confirm? What if a release and confirm arrive simultaneously? What if the cleanup job fires while a screening is still running? Each required a separate fix in the Lua scripts, and each has a concurrency integration test.
>
> The rest of the architecture is DDD with clean layering: domain layer has zero external imports, application layer uses use cases over repository interfaces, infrastructure implements those interfaces. Full observability stack with OpenTelemetry, Prometheus, Grafana, and trace-to-log correlation.
>
> If I were rebuilding it, I'd start with the domain model before touching any infrastructure, and I'd write the concurrency tests before the service code."

---

## System Design Interview Version

If the interviewer says "let's design a movie ticket booking system from scratch":

**Phase 1 — Functional requirements (2 min)**

Clarify scope:
- "Are we handling the full booking lifecycle — browse, hold, pay, confirm, cancel?"
- "What's the scale target? A single cinema, a chain, Netflix-level?"
- "Real-time seat map or eventual consistency on availability?"
- "What's the hold window? 10 minutes is typical."

**Phase 2 — High-level design (5 min)**

Start simple:
```
Client → API Server → [Redis for locks, MongoDB for records]
```

Then explain the data split:
- "Redis is the source of truth for seat availability — ephemeral, high-frequency, concurrency-critical"
- "MongoDB is the durable record for confirmed bookings — queryable, append-mostly"
- "These concerns belong in different stores"

**Phase 3 — The locking mechanism (10 min — the meat)**

Walk through the problem:
1. Naive approach has a race window
2. Single key: `SET NX` is atomic. Multi-key: need a script.
3. Lua atomicity: the whole script runs as one command
4. Rollback pattern for partial conflicts
5. TTL for automatic expiry

Draw the state machine on the whiteboard:
```
held (TTL) → confirmed (no TTL)
           → released (key deleted)
           → expired (TTL fires, key gone)
```

**Phase 4 — Scaling (5 min)**

Address each bottleneck:
- "The N+1 Redis problem: 120 GET + 120 TTL calls per availability poll → pipeline"
- "Redis Cluster for horizontal scaling: hash tags ensure seat keys for a screening land in the same slot"
- "Multiple API servers: stateless, all pointing at same Redis"
- "Real-time updates: SSE instead of 2s polling reduces Redis load 95% at scale"

**Phase 5 — Failure modes (3 min)**

Show you've thought about this:
- "Redis down: availability endpoint returns 503, no new holds possible, confirmed bookings safe in MongoDB"
- "MongoDB down after Redis hold: compensating transaction releases the Redis lock"
- "Redis data loss: rebuild from confirmed bookings in MongoDB"

---

## Behavioral Questions (STAR Format)

### "Tell me about a challenging technical problem you solved"

**Situation**: Building a seat reservation system with correctness guarantees under concurrent load.

**Task**: Design a multi-seat locking mechanism that is atomic, fast enough for real-time availability polling, and handles all edge cases.

**Action**:
1. Identified why database transactions were incorrect for this use case (read contention under polling load)
2. Chose Redis Lua scripts for atomic multi-seat locking
3. Implemented three scripts: hold (with rollback), confirm, release
4. Found three additional race conditions through systematic analysis
5. Fixed each with targeted script modifications
6. Verified with a 10,000-goroutine integration test using real Redis via testcontainers

**Result**: A seat locking system that is provably correct under concurrent load, with sub-5ms latency on the critical booking path, and documented trade-offs for when to scale beyond single-node Redis.

---

### "Tell me about a time you made an architectural decision under uncertainty"

**Situation**: Choosing between Redis and MongoDB transactions for seat locking.

**Task**: Select the right data store for the locking mechanism given competing constraints.

**Action**:
1. Identified the core tension: correctness (both can provide it) vs. performance under the seat map polling pattern
2. Benchmarked the polling load: 270 viewers × 120 seats × 0.5 polls/s = 16,200 reads/second
3. Modelled the contention: with MongoDB row locks, reads and writes fight for the same resource peak demand
4. Evaluated Redis: reads (availability polling) are completely independent from writes (Lua lock scripts) — no contention

**Result**: Chose Redis. The trade-off was operational complexity (two databases instead of one). Mitigation: Redis holds ephemeral state and can be rebuilt from MongoDB — a Redis failure is degraded availability, not data loss.

---

### "Tell me about a time you improved code quality or caught a bug before it reached production"

**Situation**: Three race conditions in the seat locking mechanism that wouldn't appear in unit tests or happy-path integration tests.

**Task**: Identify and fix timing-dependent bugs in concurrent Redis operations.

**Action**:
1. Systematically analysed every state transition in the reservation lifecycle
2. Identified RC-01: concurrent confirm + release — release must not win after confirm
3. Identified RC-02: TTL expiry between checkout and confirm — confirm must detect expired reservation
4. Identified RC-03: cleanup job fires while screening still running — guard with end_time comparison
5. Fixed each with targeted Lua script modifications
6. Wrote dedicated integration tests for each race condition with real Redis

**Result**: Three potential production bugs caught during design. Each test can be run in isolation to verify the fix. The fixes are in the Lua scripts (4 lines added), making them easy to audit.

---

### "Tell me about a time you had to balance technical debt with delivery"

**Situation**: The application service had a `b.ID = uuid.New().String()` assignment — the booking aggregate's ID was being assigned externally by the service rather than internally by the aggregate.

**Task**: Decide whether to fix this architectural smell immediately or document it and continue.

**Action**:
1. Assessed the risk: the bug means IDs are assigned inconsistently if more than one code path creates bookings
2. Assessed the effort: 30-minute fix in the aggregate's `New()` factory
3. Assessed timing: it was part of a larger domain hardening milestone (M3) with 8 other related changes
4. Decision: document it as TD-12 in the technical debt register, fix it as part of M3 rather than a one-off commit that might have unintended side effects

**Result**: TD-12 is in the refactor plan, M3 is the third of eight milestones, and the fix is grouped with related domain improvements that all need to happen together for a coherent migration.

---

## Deep Technical Questions

### "How does your Redis Lua script handle the case where the Redis instance dies mid-script?"

> "If Redis dies mid-Lua script, the script doesn't partially commit — the uncommitted changes are lost when the server restarts. From Redis's perspective, the script either ran to completion (and was logged to the AOF/RDB) or it didn't run at all. The client will see a connection error and can retry safely because `SET NX` is idempotent — trying to set a key that was already set in a completed execution just returns nil and no keys change."

### "Could you use Redlock instead of a single Redis instance?"

> "Redlock provides stronger guarantees under network partitions — specifically, it prevents a lease from being valid on two servers simultaneously if one server's clock drifts. For this use case, I don't think the added complexity is worth it. Seat holds are TTL-bounded — a lock expiring early means a user has to retry, not a safety failure. Redlock requires three or more Redis instances and adds ~100ms of latency per lock acquisition (sequential writes to all nodes). Redis Sentinel gives me HA with ~20s failover and no latency overhead. I'd use Redlock if I needed strict fencing tokens for a critical mutation, but seat reservations don't meet that bar."

### "What's the failure mode if MongoDB is down when you try to persist the hold?"

> "The write ordering is: Redis first, MongoDB second. If Redis succeeds and MongoDB fails, the application runs a compensating transaction — it calls luaRelease on the Redis keys that were just locked. This ensures the seat doesn't appear held when no MongoDB record exists. The user sees a 500 error and can retry. If the compensation itself fails — Redis is now also down — the seat is stuck as held until the TTL expires (maximum 10 minutes). This is logged as a P0 alert."

### "How would you handle a screening with 500 seats instead of 120?"

> "The pipeline approach scales well — it's still one network round trip regardless of seat count. The hold script is O(N) in Redis commands, but N is at most 4 (the max seats per booking). The availability read is the real concern at 500 seats: 500 GET + 500 TTL = 1000 Redis commands per poll, but still one round trip via pipeline. At that scale I'd also consider switching from individual keys to a Redis hash: one `HGETALL seat:{screeningID}` command returns all statuses in one value. The trade-off is that the Lua lock scripts become more complex because they need to work with hash fields."

### "Walk me through your Clean Architecture. How is it different from just having folders?"

> "The key is the dependency rule — enforced, not just aspirational. The domain layer imports nothing. Not Gin, not Redis, not MongoDB, not uuid. This means I can unit-test every aggregate and value object without starting any infrastructure. When I want to change from MongoDB to Postgres, I write a new implementation of the repository interface in the infrastructure layer — nothing in the domain or application layer changes. The test for this: grep for external imports in `internal/domain/`. If it finds anything, the build fails. The pattern only has teeth when it's automated."

---

## "What Would You Do Differently?"

This question separates candidates who shipped something from candidates who learned something.

**Honest answer:**

> "Three things. First, I'd design the domain model before touching any infrastructure. I built the MongoDB schema first and then built the aggregate to fit it — that's backwards. The aggregate should express the business rules and the schema should accommodate the aggregate. The evidence: I have JSON tags in domain struct fields, which is an infrastructure concern that leaked in.
>
> Second, I'd write the concurrency tests before the service code. Not for TDD reasons, but because the tests forced me to define what 'correct' means precisely. I found all three race conditions by writing tests first and watching them fail in interesting ways.
>
> Third, I'd start with the ubiquitous language and enforce it everywhere. I still have `Showtime` and `Session` in the codebase when the domain model says `Screening` and `SeatReservation`. Every time a developer reads the code, they have to translate. That translation cost is small per read and enormous across a team over a year."

---

## Questions to Ask the Interviewer

These signal genuine curiosity and contextual thinking:

- "For a system like this at your scale, how do you handle the seat availability polling — is it still short-poll, or have you moved to SSE or WebSockets?"
- "How do you think about the boundary between Redis and your primary database for stateful operations like this? Is there a framework you use for those decisions?"
- "The three race conditions I found were all timing-related. How does your team approach testing for that kind of concurrency bug — is it automated, or does it require load testing?"
- "I used a monorepo with separate backend and frontend — how do you handle that coordination at your organisation?"
