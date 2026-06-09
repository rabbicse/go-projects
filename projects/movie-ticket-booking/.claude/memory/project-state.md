# Project State

_Last updated: 2026-06-08_

## Current Phase: Phase 15 — ALL PHASES COMPLETE ✓

### Completed

- [x] Phase 0: All 8 analysis documents generated in `.claude/analysis/`
- [x] Phase 1: Architecture review — `.claude/architecture/architecture-review.md`
  - Dependency graph with violation callouts
  - Domain boundary assessment (Catalog + Reservation contexts)
  - Aggregate integrity table (Booking + Movie)
  - Business rule placement analysis
  - Concurrency grade per dimension
  - 12 anti-patterns catalogued
  - Coupling matrix
  - Frontend architecture assessment
  - Overall grade: B- with detailed per-dimension scores
  - `repository-overview.md` — tech stack, data flow, key numbers
  - `backend-analysis.md` — layer compliance, issues per layer
  - `frontend-analysis.md` — component breakdown, gaps
  - `concurrency-analysis.md` — Lua script correctness, race conditions
  - `architecture-smells.md` — 18 numbered smells with severity
  - `technical-debt.md` — 32 debt items, prioritised + effort estimates
  - `security-analysis.md` — 11 security findings with severity
  - `scalability-analysis.md` — bottleneck analysis, scale ceilings

### Pending

- [x] Phase 1: Architecture Review (formal review docs)
- [x] Phase 2: Domain Discovery — `.claude/architecture/domain-model.md`
  - 5 bounded contexts identified (Catalog, Reservation, Booking, Identity, Payment)
  - 9 domain events defined
  - Ubiquitous language corrections (Showtime→Screening, Session→SeatReservation, Hall→Screen)
  - Current vs target model delta table
  - Context map with integration patterns
- [x] Phase 2: Domain Discovery — `.claude/architecture/domain-model.md`
- [x] Phase 3: DDD Design — `.claude/architecture/ddd-design.md`
- [x] Phase 4: Clean Architecture Design — `.claude/architecture/clean-architecture.md`
- [x] Phase 5: Backend Refactoring Plan — `.claude/tasks/backend-refactor-plan.md`
- [x] Phase 6: Concurrency Review — `.claude/analysis/concurrency-review.md`
- [x] Phase 7: Production Architecture — `.claude/architecture/production-architecture.md`
  - Full topology: CDN → LB → API Gateway → Pod Pool → Redis Sentinel + MongoDB RS + NATS
  - Component selection rationale (Kong, NATS JetStream, Redis Sentinel, distroless image)
  - Horizontal scaling strategy per tier (1 pod → 30 pods path)
  - Failure mode analysis table with detection/recovery times
  - Choreography-based Saga pattern for distributed consistency
  - Observability stack: Prometheus/Grafana/Loki/Tempo/AlertManager with specific metrics
  - Kubernetes namespace layout + HPA config
  - 4 scaling tiers with cost estimates
  - Redis Cluster hash tag requirement documented
  - 3 race conditions found and documented (RC-01 confirm+release, RC-02 TTL boundary, RC-03 cleanup)
  - Deadlock proof (no application-level locks)
  - Starvation proof (N+1 slows but doesn't starve)
  - Lua script fixes for RC-01 and RC-02 (status guard + EXISTS guard)
  - Locking strategy comparison: pessimistic NX vs optimistic CAS vs Redlock vs Postgres advisory locks
  - Production recommendations: Redis Sentinel, cluster hash tags, idempotency keys, context timeouts
  - 7 missing concurrency tests identified
  - 8 milestones, 24 steps, each independently verifiable
  - M1 Quick Wins (config IPs, admin env, rate limit duplicate, fire-and-forget fix)
  - M2 Shared Kernel (Money error, UserID VO, Pagination, DomainEvent interface)
  - M3 Domain Hardening (self-assign ID, Expire(), domain events, invariant fix)
  - M4 Package Restructure (catalog, reservation packages + compat bridges)
  - M5 Application Layer (commands/queries, event dispatcher, event handlers)
  - M6 Infrastructure (N+1 pipeline fix, confirmed-seat cleanup, RequestID, rate limit)
  - M7 Interface Layer (DTOs without json tags, error mapping, endpoint rename)
  - M8 Verification (arch checklist, full test suite, load test, manual e2e)
  - Dependency rule diagrams + full wiring (main.go composition root)
  - Layer definitions with allowed/forbidden imports per layer
  - Framework confinement table (Gin, Redis, Mongo, slog)
  - DTO mapping strategy (no JSON tags in domain)
  - Middleware stack with RequestID fix
  - Testing strategy per layer (domain=pure, app=mocks, infra=testcontainers, handler=httptest)
  - Architecture validation checklist (grep assertions)
  - Full Go struct/method sketches for all 5 bounded contexts
  - PopEvents() pattern for domain event collection
  - ACL pattern: Catalog→Reservation cross-context read
  - Event-driven pattern: Reservation→Booking via dispatcher
  - In-process synchronous EventDispatcher design
  - Migration delta table (current → target)
- [ ] Phase 3: DDD Design (ddd-design.md)
- [ ] Phase 4: Clean Architecture Design (clean-architecture.md)
- [ ] Phase 5: Backend Refactoring Plan (backend-refactor-plan.md)
- [ ] Phase 6: Concurrency Review (formal review doc)
- [ ] Phase 7: Production Architecture Design
- [x] Phase 8: Frontend Modernization — `.claude/architecture/frontend-architecture.md`
  - Feature-based folder structure: `features/{catalog,booking,admin}/`
  - Booking state machine: discriminated union + `useReducer` (replaced ad-hoc `useState` stages)
  - `useBookingFlow` custom hook: encapsulates hold/confirm/cancel mutations + state transitions
  - `useSeatAvailability`: TanStack Query with `refetchIntervalInBackground: false`
  - `useCountdown`: isolated countdown timer (no more setInterval in god component)
  - `useUserID`: localStorage (fixes sessionStorage refresh loss)
  - Decomposed 436-line god component → `SeatSelectionFeature` + 3 panel components
  - Admin forms: React Hook Form + Zod schemas with full validation
  - Typed API layer split into `lib/api/{catalog,booking,admin}.ts`
  - shadcn component inventory (11 components mapped to usage)
  - `sendBeacon` on `beforeunload` for reservation cleanup
  - 15-step migration plan with risk/effort estimates (~16h total)
  - Fixes: TD-21 (unconditional polling), TD-22 (god component), TD-23 (no state management),
           TD-24 (sessionStorage), TD-25 (magic PAYMENT_TTL_S), TD-28 (no error boundaries)
- [x] Phase 9: API Design — `.claude/docs/api-design.md`
  - Resource rename catalog: showtimes→screenings, sessions→reservations, /seats→/availability
  - Full endpoint catalog: 14 endpoints with request/response schemas + all status codes
  - Consistent error envelope with machine-readable code catalogue (16 codes)
  - Dual pagination: offset for movies/admin, cursor for booking history
  - Rate limiting per endpoint class (10 req/60s for POST /reservations — Redis INCR)
  - Caching strategy per endpoint (public max-age for catalog, no-store for availability)
  - Idempotency-Key header spec for hold + confirm (60s Redis cache)
  - OpenAPI v3 diff for renamed paths + reusable Money, SeatStatus, ErrorResponse schemas
  - SSE alternative to 2s polling (reduces Redis load 95% at scale)
  - 301 backward-compat redirects for old showtime/session paths (M7 migration bridge)
  - CORS production config (env var, not wildcard)
  - 10 current API issues catalogued with fix references into backend-refactor-plan milestones
- [x] Phase 10: Database Design — `.claude/docs/database-design.md`
  - Two-store architecture rationale (Redis = availability source of truth, MongoDB = durable record)
  - ASCII ERD: Movie → Screening (1:N), Screening → Booking (1:N), no Users collection
  - Full BSON document specs for movies, screenings, bookings (current vs target)
  - Money flattened: nested { amount, currency } → price_cents + currency fields
  - Embedded showtimes array removed from Movie (SM-09 fix) — secondary query on screenings
  - Index catalogue: 12 indexes across 3 collections with rationale
  - TTL index on bookings.expires_at with sparse: true (auto-cleanup of held bookings)
  - Partial index on (user_id, confirmed_at) where status=confirmed (~30% smaller)
  - 6 query patterns documented with index usage and cost analysis
  - Redis key schema: seat:{screeningID}:{seatID}, reservation:{reservationID}
  - Lua script inventory: luaHold, luaConfirm (RC-02 fix), luaRelease (RC-01 fix)
  - Redis pipeline fix for GetSeatStatuses: 240 serial ops → 1 pipeline (TD-18)
  - Redis Cluster hash tag requirement: seat:{screeningID}:{seatID} — all seats same slot
  - Write ordering + compensation pattern for Redis→MongoDB consistency
  - Confirmed-seat cleanup job design (RC-03 fix, TD-04)
  - Redis rebuild-from-MongoDB disaster recovery procedure
  - Volume estimates: <2 MB Redis, <1 GB MongoDB after 1 year at demo scale
  - MongoDB migration plan for M1/M4/M7 milestones (TTL index, collection rename, schema)
  - 10 current database issues cross-referenced to backend-refactor-plan milestones
- [x] Phase 11: Observability — `.claude/docs/observability.md`
  - Three-pillar architecture: Prometheus (metrics) + Tempo (traces) + Loki (logs)
  - SLIs and SLOs: hold P99 < 100ms, availability 99.9%, confirm success > 99%
  - OTel SDK bootstrap: tracer provider (OTLP→Tempo), meter provider (Prometheus exporter)
  - 10% sampling in production, 100% in dev (TraceIDRatioBased)
  - Instrumentation points: otelgin (Gin), redisotel (Redis), otelmongo (MongoDB)
  - Middleware stack order: RequestID → Tracing → Metrics → Logging → CORS → RateLimit
  - Metrics catalogue: 7 HTTP + 6 booking domain + 2 Redis (auto) + 3 MongoDB (auto) + 4 Go runtime
  - High-cardinality label warning: use c.FullPath() not c.Request.URL.Path
  - Prometheus exemplars linking histograms to Tempo traces
  - Trace hierarchy for hold flow and availability polling documented
  - Request-scoped slog logger with trace_id + span_id + request_id
  - PII logging prohibition: no tokens, passwords, payment data
  - 3 Grafana dashboards: Service Overview, Booking Domain, Infrastructure
  - 10 AlertManager rules: 4 availability/latency, 2 booking domain, 2 infra, 2 runtime
  - Full Docker Compose additions: Prometheus, Grafana, Tempo, Loki, Promtail
  - Grafana data source provisioning with trace↔log↔metrics correlation links
  - 12-step M6 implementation checklist mapped to backend-refactor-plan milestones
- [x] Phase 12: Testing Strategy — `.claude/docs/testing-strategy.md`
  - Testing pyramid: domain unit (100%) → app unit (90%) → handler unit (80%) → integration → concurrency → load
  - Test inventory: 1 existing test, 40+ missing tests identified across all layers
  - Domain tests: Booking aggregate state machine, Money.Add error (not panic), Movie overlap invariant
  - Application tests: 6 service scenarios including compensation test (MongoDB fail → Redis released)
  - Handler tests: 8 scenarios via httptest — status codes, error envelope, max-seats enforcement
  - Integration tests: testcontainers setup, 9 Redis/MongoDB scenarios
  - 7 concurrency tests: RC-01 confirm+release, RC-02 TTL boundary, RC-03 cleanup safety, compensation
  - k6 thresholds: P99 hold < 100ms, error rate < 1%, availability P95 < 50ms
  - Frontend tests: bookingReducer state machine (Vitest), useCountdown hook
  - Builder pattern for test data: BookingBuilder, ScreeningBuilder
  - Coverage measurement + 80% CI enforcement (bc comparison)
  - CI pipeline: unit + race detector in parallel, integration with Docker, frontend type-check
  - Full test file location map across backend and frontend
- [x] Phase 13: Security Review — `.claude/docs/security.md`
  - Threat model: 4 actors, asset sensitivity table, attack surface diagram
  - 16 findings (SEC-01 through SEC-16) with severity, OWASP mapping, code fixes
  - P0 criticals: hardcoded admin:admin (SEC-01), hardcoded 192.168.0.50 IPs (SEC-02)
  - P1 highs: CORS wildcard, no rate limiting, no body size limit, missing security headers
  - P2 mediums: no ownership validation (IDOR), error message leakage, input validation gaps
  - Redis sliding window rate limiter implementation (per-endpoint limits)
  - BodyLimitMiddleware: http.MaxBytesReader 1MB cap
  - SecurityHeadersMiddleware: HSTS, X-Frame-Options, nosniff, Permissions-Policy
  - Next.js CSP headers config in next.config.ts
  - BSON injection: current code safe (bson.D not bson.M), documented safe pattern
  - Distroless Dockerfile for backend (nonroot, no shell, minimal attack surface)
  - Non-root Next.js Dockerfile (uid 1001)
  - File-based secret pattern: ADMIN_PASSWORD_FILE env var for Docker/K8s secrets
  - JWT auth design (future): RS256, 15-min access token, httpOnly cookie, refresh token
  - OWASP Top 10 coverage table: A01/A05/A07 are red, A03/A09/A10 are green
  - Remediation roadmap: P0-P4 ordered by severity × exploitability with effort estimates
  - Security testing scripts: rate limit, CORS rejection, body size 413 tests
- [x] Phase 14: Portfolio Documentation — README.md rewritten
  - Hook leads with the hard problem (10k concurrent goroutines, atomic locking)
  - Bounded context table with integration patterns (ACL, domain events)
  - Clean Architecture layers with CI-enforced grep assertion
  - Full Lua script with RC-01/02/03 race condition table
  - Tech stack with explicit rationale for each choice (not just a list)
  - Three getting-started options: Docker Compose, local, with observability
  - Load test thresholds table (P99 <100ms, P95 <50ms, <1% errors)
  - Design decisions section with trade-off reasoning for Redis/Redlock/MongoDB/DDD/frontend
  - Full phase index table linking all 17 architecture documents in .claude/
  - Prioritised roadmap: Immediate (P0 security) → Near term → Medium → Long
  - Replaced old "Phase 2 observability coming" placeholder with live observability section
  - SLO table with alert firing conditions
  - Business metrics table with descriptions
- [x] Phase 15: Marketing Assets — `.claude/marketing/`
  - project-story.md — narrative arc: the itch, the Lua insight, the race conditions, DDD click, observability revelation; "what I'd tell my past self"; audience-differentiated value summary
  - linkedin-post.md — 3 variants: hook-first (for reach), storytelling (for engagement), technical depth (for engineering audience); canned comment replies for common follow-up questions
  - technical-case-study.md — engineering blog style: double-booking problem, why not DB transactions, Lua script with properties table, lifecycle (3 scripts), N+1 pipeline analysis, write ordering, verification section, "what this doesn't solve," lessons
  - interview-discussion-guide.md — 30s elevator pitch, 5-min technical summary, system design interview structure (5 phases), 4 STAR behavioral answers, 5 deep technical Q&A, "what would you do differently," questions to ask the interviewer
  - architecture-walkthrough.md — scripted 20-30 min presentation: opening hook, system overview, clean architecture layers (with CI grep assertion), DDD bounded contexts (ACL, ubiquitous language), concurrency deep-dive (with Lua, 3 race conditions, proof), observability, known issues/honest self-assessment, 5 Q&A responses

## Key Decisions Made

None yet — analysis only. No code changed.

## Top Risks Identified

1. **MongoDB save failure on hold is silently swallowed** (TD-03) — biggest data integrity risk
2. **Hardcoded `192.168.0.50` IPs** (TD-01 / SM-01) — breaks fresh clone
3. **Admin `admin:admin` in source** (SEC-02) — critical security issue
4. **GetSeatStatuses N+1 Redis calls** (TD-18) — performance cliff at ~270 concurrent viewers
5. **Confirmed seats never cleaned from Redis** (TD-04) — memory leak

## Architecture Snapshot

The project is a well-structured DDD + Clean Architecture demo with a genuinely correct concurrency implementation (Lua atomic locks). The main gaps are: no authentication, fire-and-forget MongoDB persistence, and a monolithic 436-line frontend component. The core engineering showcase (atomic multi-seat Redis lock under 10k concurrent goroutines) works correctly and is well-tested.
