# Technical Blog Series

A content strategy for blogging or social media based on this project.

---

## Series Overview

**Series Title**: Building a Production-Grade Seat Booking System

**Target Audience**: Mid-to-senior backend engineers who know the basics and want to see real-world patterns applied.

**Platform**: Medium, Dev.to, Substack, or personal blog.

**Cadence**: One post per week (7 posts = 7-week series)

---

## Post 1 — The Race Condition That Breaks Every Naive Booking System

**Hook**: "Two users click 'Hold Seat' at the same millisecond. Here's what most booking systems get wrong."

**Content**:
- Explain the TOCTOU race condition with a timing diagram
- Show why database-level transactions don't fully solve it for distributed seat maps
- Introduce the problem space: why seat booking is harder than it looks

**Key diagram**: Two concurrent requests racing for the same seat, showing where the naive implementation fails.

**Code snippet**: The broken version (read-check-write) vs the Redis NX version.

---

## Post 2 — Lua Scripting in Redis: Atomic Multi-Seat Locking

**Hook**: "One round trip. All-or-nothing. No retry logic. Here's how Redis Lua scripts solve the seat reservation problem correctly."

**Content**:
- How Redis Lua scripts achieve atomicity (single-threaded event loop)
- The `luaHoldSeats` script: SET NX with rollback
- Why not WATCH/MULTI/EXEC or Redlock
- The two additional race condition guards (RC-01, RC-02)

**Code snippet**: The full `luaHoldSeats` Lua script with explanation.

**Key takeaway**: Lua scripting is underused by Go developers. It's the right tool for multi-key atomic operations.

---

## Post 3 — Clean Architecture in Go: A Real Example

**Hook**: "Most Clean Architecture tutorials use shopping carts. Here's a booking system with a real concurrency problem showing why the layers actually matter."

**Content**:
- The 4-layer structure: domain, application, infrastructure, interfaces
- Why domain/booking has zero external imports
- How the MongoDB v1→v2 upgrade was contained to one directory
- The `apierr.HTTPStatusFor()` pattern for error translation

**Code snippet**: `domain/booking/booking.go` — the aggregate root with state machine.

**Key takeaway**: Layer boundaries only pay off when tested against a real change (like a driver upgrade).

---

## Post 4 — Domain Events in Go: Decoupling Booking from Notifications

**Hook**: "Your booking aggregate shouldn't know about email. Here's how domain events let you add downstream consumers without touching the domain."

**Content**:
- What domain events are and why they matter
- The `PopEvents()` pattern on aggregates
- The in-process dispatcher (start here, replace later)
- How to swap to Kafka without changing the domain or application layer

**Code snippet**: `domain/booking/events.go` + `application/events/dispatcher.go` + handler registration in `main.go`.

---

## Post 5 — The N+1 Redis Problem: Pipelining Seat Status Queries

**Hook**: "Getting the seat map for a 200-seat hall using N Redis calls is 200x slower than it needs to be. Here's the pipelined solution."

**Content**:
- Why serial GET+TTL calls are O(N) in network round trips
- Redis pipelining: batching multiple commands in one round trip
- The three-step algorithm: SCAN → pipeline GET+TTL → pipeline session lookups
- HeldByMe resolution: why session owner lookup is a separate pipeline

**Code snippet**: `GetSeatStatuses` from `seat_lock_repository.go` with step annotations.

**Key metric**: 200 seats × 2ms RTT = 400ms naive. 3 pipelines × 2ms = 6ms optimized.

---

## Post 6 — Compensating Transactions Without a Saga Framework

**Hook**: "Your Go service holds a Redis lock and then MongoDB fails. Now what?"

**Content**:
- The distributed consistency problem between Redis and MongoDB
- What compensating transactions are and when to use them
- The `HoldSeats` service method: lock → save → compensate on failure
- The MongoDB partial TTL index as a self-healing backup mechanism
- What happens when the compensation itself fails

**Code snippet**: The compensating transaction block from `application/booking/service.go`.

**Key takeaway**: You don't need a saga framework for this pattern. A simple `defer` or explicit rollback is enough for two-step operations.

---

## Post 7 — Honest Self-Review: What's Missing Before This Goes to Production

**Hook**: "I ran a Staff Engineer review on my own portfolio project. Here's every gap I found."

**Content**:
- The 5 real bugs found in QA testing (F-01 through F-05)
- The OWASP coverage gaps (no user auth, no rate limiting, CORS too permissive)
- The scalability analysis: where the system breaks at 10K and 100K users
- The production readiness checklist: what it would actually take
- The value of honest self-assessment in portfolio projects

**Key takeaway**: A portfolio project that includes its own honest engineering review demonstrates Staff Engineer-level thinking. Building something that works is junior. Knowing *why* it works and *where* it breaks is senior.

---

## Content Calendar

| Week | Post | Estimated Reads |
|---|---|---|
| 1 | Race Conditions in Booking Systems | High (broad appeal) |
| 2 | Redis Lua for Seat Locking | Medium (Redis audience) |
| 3 | Clean Architecture in Go | High (Go community) |
| 4 | Domain Events in Go | Medium (DDD audience) |
| 5 | Redis N+1 + Pipelining | Medium (performance focus) |
| 6 | Compensating Transactions | Medium (backend engineers) |
| 7 | Honest Self-Review | High (career/portfolio angle) |

---

## Repurposing Strategy

Each blog post can become:
- **LinkedIn post**: The hook + 3 key points + link to full post
- **Twitter/X thread**: Each code snippet as a separate tweet in a thread
- **GitHub README section**: Technical findings documented in the repo
- **Interview talking point**: "I wrote about this — let me explain the tradeoff"
