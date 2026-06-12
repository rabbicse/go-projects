# LinkedIn Showcase Post

Ready-to-publish content for LinkedIn. Choose one variant or combine.

---

## Variant A — Technical Deep-Dive Post

**Title**: I built a cinema seat booking system — here's the distributed systems problem most tutorials skip

---

Seat reservation systems look simple until you face this scenario:

Two users, same seat, clicking "Hold" at exactly the same time.

A naive implementation reads seat availability, checks if it's free, then writes the lock. Between the read and the write, another request can slip in. Both users get the seat. You've double-booked.

This is a classic race condition called TOCTOU (Time of Check to Time of Use). Ticketmaster, United Airlines, and every real booking system has solved this problem. Here's how I solved it in my portfolio project:

**The solution: Redis Lua scripting**

Redis executes Lua scripts atomically — no other command can run between iterations. I wrote a script that:
1. Tries to SET each seat key with NX (only if not exists) and a 10-minute TTL
2. If any seat is already taken, the script rolls back ALL previously locked seats in the same execution
3. Returns either success (all seats locked) or failure (seats freed, try again)

Zero chance of partial holds. One network round trip. No client retry logic.

**But there's more**

What happens if the user closes the browser mid-hold? Redis TTL auto-deletes the seat keys after 10 minutes, freeing the seats automatically.

What if Redis confirms the booking but MongoDB fails? Compensating transaction — immediately release the Redis locks so the seats aren't stuck in a phantom hold state.

What about a user confirming an expired hold? The confirm Lua script checks EXISTS before persisting — if the hold TTL already fired, the confirm fails gracefully.

**The full project**

Beyond the concurrency model, I built:
→ Clean Architecture with DDD (aggregates, domain events, bounded contexts)
→ Real-time seat map (Redis pipelines — 3 round trips regardless of hall size)
→ Prometheus + Grafana observability
→ Non-root Docker containers with health checks
→ k6 load tests validating exactly-one-wins under concurrent hold attempts

The codebase, architecture docs, and my engineering self-review are all on GitHub.

What distributed systems challenges have you solved recently?

---

#golang #distributedsystems #systemdesign #redis #cleanarchitecture #ddd #softwareengineering #backend

---

## Variant B — Career/Portfolio Post

**Title**: After months of building, I've completed my most ambitious portfolio project

---

I challenged myself to build a cinema seat booking system that would hold up to scrutiny from a Staff Engineer or Principal Architect.

Not just "it works." But: why does it work? What breaks under load? What are the security gaps? What would it take to put this in production?

Here's what I built:

🎬 **Full-stack booking system** (Go backend + Next.js frontend)
⚡ **Atomic seat reservation** via Redis Lua scripting — no double-bookings, mathematically
🏗️ **Clean Architecture + DDD** — 4 layers with strict dependency inversion
📊 **Production observability** — Prometheus metrics, Grafana dashboards, structured logging
🐳 **Docker Compose** — full stack in one command, health-checked service startup
🧪 **Three test tiers** — unit, integration (testcontainers), k6 load tests

Then I did something most portfolio projects skip:

I wrote an honest engineering review. Security audit with OWASP coverage. Scalability analysis for 1K/10K/100K concurrent users. Performance measurements with a real remote database. A product backlog of what's missing before it's production-ready.

The audit found 5 real issues and 20 backlog items. That's not failure — that's the difference between knowing what you built and just having built it.

Stack: Go 1.24, Redis 7, MongoDB 7, Next.js 15, Docker, Prometheus, Grafana, testcontainers-go, k6

Full docs and architecture diagrams on GitHub (link in comments).

---

#golang #nextjs #portfolio #distributedsystems #redis #mongodb #cleanarchitecture #softwareengineer #backend #hiring

---

## Variant C — Short Insight Post

**Title**: The Redis trick that makes seat booking systems correct

---

Cinema seat selection: two users click "Hold" on seat A12 simultaneously.

Who wins?

The naive answer is "whoever's request arrives first." But "first" in a distributed system is fuzzy — network jitter, OS scheduling, and database latency mean two requests can interleave in ways that both think they arrived first.

The correct answer: **whoever's Lua script runs on the Redis server first.**

Redis executes Lua scripts atomically. While your script runs, no other command executes. So you can write:

```lua
SET seat:A12 {session} NX EX 600
```

If NX fails (key exists), the seat is taken. No race. One round trip.

The tricky part is holding multiple seats (users often select 2–4). If seats A12, A13, A14 are requested and A14 is taken, you need to roll back A12 and A13 atomically. That's also doable in Lua — the script cleans up its own partial work before returning an error.

This is the pattern I implemented in my cinema booking system. Full details in the GitHub repo.

---

#redis #golang #distributedsystems #softwareengineering #systemdesign
