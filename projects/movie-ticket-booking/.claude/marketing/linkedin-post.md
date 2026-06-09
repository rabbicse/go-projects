# LinkedIn Posts

_Three variants — short, medium, and technical. Pick one or mix elements._

---

## Variant A — Hook-First (recommended for reach)

**Most booking systems have a bug they've never noticed.**

When two users click the same seat at the same millisecond, the typical implementation — check availability, then book — has a race window. One seat, two successful confirmations. Both users show up. One gets turned away.

I built a cinema booking system to confront this problem head-on, not work around it.

The solution: a Redis Lua script that locks all requested seats atomically in a single server-side execution. All seats are reserved, or none are — with automatic rollback if any seat is taken. This guarantee holds under 10,000 concurrent goroutines. I know, because there's an integration test that proves it.

Beyond the concurrency showcase, the project is a full-stack demonstration of patterns I care about:

→ Domain-Driven Design with five bounded contexts and aggregate invariants that make invalid states unrepresentable
→ Clean Architecture with a hard rule: the domain layer has zero external imports (enforced by grep in CI)  
→ Production observability wired end-to-end: OpenTelemetry → Prometheus → Grafana → Loki → Tempo
→ A full test pyramid from domain unit tests to k6 load tests across four traffic scenarios

The codebase also has a 24-step refactoring plan, a 32-item technical debt register, and a security review that found 16 findings — because knowing what's missing is as important as knowing what you built.

Stack: Go + Gin, Next.js 15 / React 19, Redis 7, MongoDB 7, Docker Compose

🔗 [GitHub link]

#golang #softwaredevelopment #architecture #distributedsystems #domaindrivendesign

---

## Variant B — Storytelling (better for engagement)

**Here's a problem that sounds easy and isn't:**

You're building a seat booking system. Two users want seat A3 at the same moment.

The naive fix is a database lock. But your seat map is polled every 2 seconds by every connected viewer — at scale, that lock creates contention at the worst possible time (popular film, opening day). You need reads to be completely independent from writes.

So I used Redis. But locking a single key with `SET NX` is easy. Locking *multiple* seats atomically — where you either get all of them or none — requires something more interesting.

The answer: a Redis Lua script. Lua scripts run atomically on the Redis server. No other command can interleave. The script attempts to lock each seat with `SET NX`. If any seat is already taken, it rolls back all previously locked keys in the same execution. All-or-nothing, in one network round trip.

Then I found the race conditions the basic Lua lock doesn't cover:
- What if the TTL expires between checkout and confirm?
- What if a release and confirm arrive concurrently?  
- What if the cleanup job fires while a screening is still running?

Each required a separate fix. Each is covered by a concurrency integration test.

The full project is a cinema booking engine: Go backend with DDD + Clean Architecture, Next.js 15 frontend with TanStack Query and a proper booking state machine, k6 load tests, and OpenTelemetry instrumentation end-to-end.

The interesting stuff is in the architecture documents, not just the code.

🔗 [GitHub link]

#golang #redis #concurrency #systemdesign #cleanarchitecture

---

## Variant C — Technical depth (for engineering audiences)

**I wrote a Redis Lua script that proves you can't double-book a seat, and then found three ways it could still fail.**

The Cinema Booking Engine is a portfolio project I built to demonstrate that I can reason carefully about correctness in distributed systems, not just wire things together.

**The interesting parts:**

**Atomic multi-seat locking** — A Lua script locks all requested seat keys with `SET NX EX` atomically. If any seat conflicts, all previously locked keys are deleted in the same script execution. 10,000 goroutines race for a single seat; exactly one wins. Verified by a testcontainers integration test.

**Three race conditions beyond the basic lock:**
1. TTL expires between checkout and confirm → `EXISTS` guard in luaConfirm
2. Release fires after Confirm → `TTL == -1` (no TTL = confirmed) check in luaRelease  
3. Cleanup deletes seats of an active screening → end_time < now() guard

**Domain-driven design that earns its keep:**
- `booking.Confirm()` returns `ErrAlreadyConfirmed` because the aggregate enforces its own state machine, not because a handler checked a flag
- Invalid states are unrepresentable at the type level
- The domain layer has zero external imports — enforced by CI

**Observability that changes how you reason:**
Prometheus exemplars link a P99 spike directly to a specific Tempo trace, which links to its Loki log lines. When the system misbehaves, you're one click from the exact request that caused it.

**Full tech stack:** Go 1.23 + Gin, Next.js 15, Redis 7, MongoDB 7, testcontainers-go, k6, OpenTelemetry, Prometheus, Grafana, Loki, Tempo

16 architecture and design documents in `.claude/` covering DDD design, clean architecture, production topology, API design, database design, testing strategy, security review, and observability.

🔗 [GitHub link]

#golang #redis #domaindrivendesign #cleanarchitecture #distributedsystems #softwaredevelopment

---

## Commenting Responses (for engagement)

If someone comments with "interesting, how does the Lua script work?":
> The key insight is that Redis Lua scripts execute atomically on the server — no other command can interleave. So I can attempt to lock N seat keys with SET NX in a loop, and if any fail, roll back the ones I've already locked, all in one script execution. The full script with rollback is in the README if you want to dig in.

If someone asks "why not use Postgres advisory locks?":
> Postgres advisory locks would work, but the seat map endpoint is polled every 2 seconds by every connected viewer, and I wanted reads to be completely independent from the locking mechanism. Redis gives me that separation naturally — locks live in Redis, the durable record lives in MongoDB.

If someone asks "what would you add next?":
> Authentication is the biggest gap right now — the ownership check on reservations works but there's no real identity system. After that: Server-Sent Events to replace the 2-second polling (95% Redis load reduction at scale), and wiring the domain events through an actual event bus rather than the in-process dispatcher.
