# Resume Bullets

Three versions of resume bullets for this project, calibrated for different target levels.

---

## Senior Engineer Version

**Cinema Booking System** — Full-Stack Go + Next.js  
*Personal project demonstrating distributed systems design and DDD*

- Built atomic multi-seat reservation using Redis Lua scripting — all-or-nothing seat locking in a single round trip, eliminating race conditions that plague naive read-check-write implementations
- Implemented Clean Architecture with strict dependency inversion across 4 layers (domain, application, infrastructure, interfaces); domain layer has zero external dependencies enabling fast, isolated unit testing
- Designed booking aggregate root with full state machine (held→confirmed/released/expired) and domain event emission (BookingCreated, Confirmed, Released, Expired), enabling pluggable downstream consumers
- Optimized Redis seat map queries from O(N) serial calls to 3 pipeline round trips regardless of hall size (SCAN + 2 pipelined batches); reduced latency by ~85% for a 200-seat hall under load
- Added compensating transaction pattern: on MongoDB write failure after Redis seat lock, automatically releases Redis keys to maintain consistency between the distributed data stores
- Delivered production-grade observability: Prometheus metrics (requests counter, latency histogram, in-flight gauge) with `c.FullPath()` labels to prevent high-cardinality label explosion; Grafana auto-provisioned

---

## Staff Engineer Version

**Cinema Booking System** — Distributed Systems Portfolio Project  
*Go 1.24 · Redis Lua · MongoDB · Next.js 15 · Docker · Prometheus/Grafana*

- Solved the seat reservation consistency problem using Redis atomic Lua scripts with roll-back semantics — compared Redlock vs WATCH/MULTI/EXEC vs Lua, selected Lua for single round-trip atomicity and zero client retry logic; defended two specific race conditions (RC-01: release-after-confirm, RC-02: confirm-after-expiry) with targeted guards in separate scripts
- Applied tactical DDD patterns throughout: Booking aggregate root enforces invariants, value objects (Seat, Money) are immutable, domain events decouple booking lifecycle from notification/analytics consumers, repository interfaces declared in domain and implemented in infrastructure
- Conducted Staff Engineer-level review of the codebase: identified 6 architecture gaps (missing JWT auth, no rate limiting, synchronous event dispatcher, no aggregate versioning, implicit CQRS, single-node infrastructure) and produced a prioritised production readiness roadmap
- Modeled 3-tier scalability analysis (1K/10K/100K concurrent users): identified Redis single-node Lua throughput ceiling (~50K scripts/sec), MongoDB write amplification at scale, and O(users) polling load; proposed Redis Cluster sharding by showtime ID and SSE replacement for polling
- Produced complete engineering portfolio: C4 architecture diagrams (context/container/component), full booking flow sequence diagram, state machine diagram, security audit (OWASP Top 10 coverage), performance review, and system design walkthrough

---

## Architect Version

**Cinema Booking System** — Reference Architecture for High-Contention Reservation Systems  
*Demonstrating Clean Architecture, DDD, distributed locking, and observability patterns*

- Designed and implemented a reference architecture for real-time seat reservation, addressing the fundamental TOCTOU race condition inherent in distributed inventory systems via Redis atomic Lua scripting (all-or-nothing multi-key NX with automatic rollback)
- Established bounded context separation (booking vs. catalog domains) with explicit aggregate boundaries, typed domain events for cross-context decoupling, and repository interfaces at domain layer for infrastructure independence — enabling infrastructure replacement without domain changes (validated during MongoDB v1→v2 driver upgrade)
- Architected multi-layer failure handling: compensating transactions (Redis→MongoDB), TTL-based automatic expiry for abandoned holds, MongoDB partial TTL index for self-healing cleanup without external cron jobs, and distinct race condition guards for confirm-after-expiry and release-after-confirm edge cases
- Produced full production readiness assessment identifying 10 gaps across auth, rate limiting, HA infrastructure, payment integration, and operational concerns; estimated 3-week remediation roadmap with P0/P1/P2 prioritization
- Authored C4 architecture diagrams, OWASP security audit, scalability analysis for 1K–100K concurrent users, performance review with measured latency baselines, 7 Mermaid diagrams, and open-source contribution templates — demonstrating technical communication at the architect level

---

## Key Metrics to Mention in Interviews

| Metric | Value |
|---|---|
| Hold latency (remote DB) | 20.8ms |
| Confirm latency | 34.0ms |
| Seat map round trips | 3 (vs O(N) naive) |
| Backend startup time | ~500ms |
| Test coverage | Unit + integration + load (k6) |
| Go backend LoC | ~3,500 |
| Frontend LoC | ~1,200 |
| Docker startup-to-healthy | ~30 seconds (full stack) |
