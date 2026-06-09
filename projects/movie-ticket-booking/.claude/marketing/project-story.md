# Project Story

_The narrative behind the Cinema Booking Engine — suitable for blog posts, conference lightning talks, and "tell me about a project" conversations._

---

## The Itch I Needed to Scratch

I had been writing distributed systems for a while, but most of my portfolio projects demonstrated breadth rather than depth. They showed I could wire together a REST API, persist to a database, and deploy to a cloud provider. What they didn't show was that I could reason carefully about the hard parts — the parts where correctness isn't obvious and where "it works on my machine" is meaningless.

I chose a cinema booking system specifically because it contains one of the most commonly mishandled problems in distributed systems: **the double-booking race condition**. It's simple enough to understand in five minutes and subtle enough that most implementations get it wrong.

---

## The Problem That Sounds Easy

Here's the naive booking flow that almost every tutorial implements:

```
1. Read seat status → available
2. Write seat status → booked
```

This works perfectly in production — right up until two users click the same seat in the same millisecond. Then you get two successful bookings for one seat. Both users show up. One gets turned away.

The fix sounds obvious: "use a lock." But which lock? How do you lock multiple seats atomically? What happens if the server dies after locking seat A1 but before locking A2? What happens when the lock expires during the 10-second window a user spends entering their payment details?

Each question reveals another edge case. The rabbit hole goes deeper than it looks.

---

## Why Redis, Not a Database Transaction

My first instinct was to use a database transaction: begin transaction → check seats → lock rows → commit. This is correct but has a problem specific to this use case.

The seat map is polled every two seconds by every connected client to show live availability. At 270 concurrent viewers, that's 540 read operations per second against the same tables being written to by the transaction. Under load, row-level locks create contention that compounds as the system scales — and "scales" here means the worst possible moment: when a popular film goes on sale.

Redis gave me something better: **sub-millisecond atomic operations with no lock contention on reads**. Redis's single-threaded command processor means Lua scripts execute as transactions without blocking anything else. Seat availability reads (the hot path) are completely independent from seat writes (the cold path).

---

## The Lua Script Insight

The breakthrough came from understanding what Redis Lua scripts actually guarantee: the entire script runs atomically on the server. No other Redis command can interleave during execution. This means I could write a script that:

1. Attempts to set all requested seat keys with `SET NX` (only if not exists)
2. If any key fails (seat already taken), deletes all previously set keys
3. Returns in one network round trip

```lua
local held = {}
for i, key in ipairs(KEYS) do
    if redis.call('SET', key, ARGV[1], 'NX', 'EX', ARGV[2]) == false then
        for _, k in ipairs(held) do redis.call('DEL', k) end  -- rollback
        return i
    end
    table.insert(held, key)
end
return 0
```

This is all-or-nothing multi-seat locking in about 10 lines of Lua. The correctness proof is simple: since the script is atomic, no other script can observe the intermediate state where some seats are locked but not others.

---

## The Race Conditions I Almost Missed

Getting the happy path right was satisfying. Then I started thinking about the unhappy paths.

**Race condition 1**: What if the user confirms their booking at the exact moment the 10-minute hold expires? The confirmation script (`luaConfirm`) calls `PERSIST` to remove the TTL. But if the TTL already fired a millisecond earlier, `PERSIST` operates on a key that no longer exists — and succeeds silently. Redis returns 0 (key not found) but doesn't error. I had to add an `EXISTS` check at the start of the confirm script.

**Race condition 2**: What if a release request and a confirmation request arrive concurrently for the same reservation? The release script (`luaRelease`) calls `DEL`. If confirm happened first and called `PERSIST`, the key has no TTL (TTL returns -1). I added a check: if `TTL == -1`, the seat is confirmed and must not be deleted.

**Race condition 3**: A background cleanup job deletes confirmed seat keys after a screening ends. But what if the cleanup timer fires early, or the clock comparison has drift? I added a guard: only delete keys for screenings where `end_time < now()`.

Finding these required thinking about the system as a set of concurrent state machines rather than a sequential workflow. None of them would have appeared in a unit test. All three required integration tests with real Redis and engineered timing.

---

## DDD: Where Architecture Clicked for Me

I knew what Domain-Driven Design was before this project. I understood the vocabulary: bounded contexts, aggregates, value objects, domain events. But I hadn't felt the *click* of why it matters.

It clicked when I tried to figure out where to put the `Session` struct. The current codebase had it in `domain/booking/repository.go` — a struct representing a Redis session living inside a MongoDB-oriented package. It wasn't an entity or a value object. It wasn't returned by a factory method. It was just a bag of data that happened to be near the booking code.

The problem: this struct had no invariants. Nothing prevented you from creating a session with an empty user ID, or a zero expiry time, or seats that didn't belong to the screening. The application code had to validate these things everywhere.

Replacing it with a `SeatReservation` aggregate — with a `New()` factory that enforces invariants and `Hold()` / `Confirm()` / `Release()` state machine methods — meant the domain was self-validating. If you have a `SeatReservation`, you know it's valid. The validation happens once, at creation, in the domain layer, not scattered across handlers and services.

That's the click: DDD isn't about folder structure. It's about making invalid states unrepresentable.

---

## The Observability Revelation

I added OpenTelemetry instrumentation late in the project, expecting it to be a checklist item. What I discovered was that it changed how I reasoned about correctness.

Before OTel: "the test passes, the system works."  
After OTel: "I can see exactly where 15ms of the 100ms P99 budget is spent, and it's in the MongoDB TTL index creation on startup."

The exemplar linking — where a Prometheus histogram data point carries a `trace_id` that takes you directly to the specific slow trace in Tempo — is the kind of feature that seems like a demo trick until you're staring at a P99 spike at 2am wondering which query is slow. Then it's the difference between 5 minutes of investigation and 3 hours.

Observability isn't about collecting data. It's about making the system's behaviour visible enough that you can reason about it the way you reason about code.

---

## What I'd Tell My Past Self

**Start with the domain, not the database.** I designed the MongoDB schema before I designed the `Booking` aggregate. This meant the aggregate grew to accommodate the schema rather than the other way around. The result was an aggregate with JSON tags in its fields — infrastructure concerns leaking into the domain.

**Write the concurrency tests first.** Not because of TDD, but because they force you to think about the hard parts before you've invested time in the easy parts. The three race conditions I found would have been production bugs if I'd written them after.

**The dependency rule is a forcing function.** "Domain has zero external imports" sounds like a style preference. In practice it forced every non-trivial design decision in the right direction. When I wanted to add a Redis client to the domain layer for convenience, the rule stopped me. The resulting design — with Redis behind a repository interface — made the domain 100% testable without any infrastructure.

**Ubiquitous language is a communication tool, not a naming exercise.** Renaming `Showtime` to `Screening` sounds trivial. But in a conversation with a domain expert (or in an interview), saying "screening" immediately signals you're thinking in their vocabulary. The code should read like the business talks, not like the database schema.

---

## What This Project Demonstrates

For a recruiter: Go, Next.js, Redis, MongoDB, Docker, full-stack capability.

For an engineering manager: architectural thinking, production mindset, attention to correctness, documentation discipline.

For a staff or principal engineer: genuine engagement with the hard problems (concurrency semantics, DDD invariants, observability design), ability to identify race conditions in distributed systems, trade-off reasoning that goes beyond "use Postgres."

The project is intentionally unfinished. The 24-step refactoring plan, the 32-item technical debt register, the security remediation roadmap — these aren't failures. They're evidence that I can assess a codebase honestly and prioritise what matters, which is a different skill from writing the code in the first place.
