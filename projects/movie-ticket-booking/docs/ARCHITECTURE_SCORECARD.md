# Architecture Scorecard

**Date**: 2026-06-10  
**Framework**: Clean Architecture + Domain-Driven Design

---

## Final Scores

| Dimension | Score | Max | Grade |
|---|---|---|---|
| Architecture | 8.0 | 10 | A- |
| Scalability | 6.0 | 10 | B- |
| Security | 5.0 | 10 | C |
| Performance | 7.5 | 10 | B+ |
| Maintainability | 8.5 | 10 | A- |
| DDD Implementation | 8.0 | 10 | A- |
| Clean Architecture | 9.0 | 10 | A |
| Documentation | 8.0 | 10 | A- |
| Production Readiness | 5.0 | 10 | C |
| **Composite** | **7.2** | **10** | **B+** |

---

## Architecture — 8.0 / 10

**What earns the score:**

The layering is textbook Clean Architecture: `domain → application → infrastructure → interfaces`, with every dependency pointing inward. The domain layer imports only the Go standard library. Repository interfaces are declared in the domain and implemented in infrastructure — the classic Dependency Inversion Principle application. The `apierr.HTTPStatusFor` function provides a clean error translation layer between domain errors and HTTP responses.

The concurrency architecture is notably strong for a portfolio project. Three Lua scripts with documented race condition fixes (RC-01, RC-02) show awareness of distributed-systems hazards that many senior engineers miss.

**What prevents 10/10:**

- No aggregate versioning / optimistic locking on `Booking` MongoDB documents
- Event dispatcher is in-process and synchronous — not durable
- `Session` is modeled as a struct, not a domain entity with invariants
- CQRS is implicit (naming convention only), not modeled as explicit command/query objects

---

## Scalability — 6.0 / 10

**What earns the score:**

The backend is stateless (no in-memory session state), which is the prerequisite for horizontal scaling. Redis seat locks are correctly per-showtime, making them naturally shardable. The pipelined `GetSeatStatuses` implementation avoids N+1 Redis calls.

**What prevents 10/10:**

- Single Redis node is a scalability ceiling at ~50K seat lock operations/second
- `GET /movies` returns all movies in one query (no pagination)
- Seat map polling every 2s creates O(users) read load; SSE would be O(1) per state change
- No caching layer for catalog data
- No demonstrated horizontal scaling (no Kubernetes deployment, no nginx upstream config)

---

## Security — 5.0 / 10

**What earns the score:**

- Security headers middleware (X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Request ID for log correlation
- Parameterized MongoDB queries (no injection vectors)
- `crypto/rand`-based UUIDs for session IDs
- MongoDB URI sanitized in logs (no credential leakage)
- Admin Basic Auth correctly implemented

**What prevents 10/10:**

- No user authentication (any `user_id` is trusted from request body)
- No rate limiting
- CORS allows all origins
- Weak default admin password committed to docker-compose.yml
- Content-Type not enforced on POST endpoints

---

## Performance — 7.5 / 10

**What earns the score:**

- Measured hold latency: 20.8ms (including 8ms network RTT to remote databases)
- Redis pipelines in `GetSeatStatuses` (2 round trips vs N+1 naive)
- All MongoDB queries have supporting indexes
- TTL partial index auto-expires abandoned holds
- HTTP timeouts configured on the server

**What prevents 10/10:**

- No catalog caching (every movie list request hits MongoDB)
- Seat polling every 2s creates unnecessary read pressure
- `ConfirmSession` does 2 Redis operations where 1 Lua script could suffice
- `GET /movies` has no pagination (full collection scan as data grows)

---

## Maintainability — 8.5 / 10

**What earns the score:**

- Self-documenting names throughout (no abbreviations, no cryptic variables)
- Error sentinel values enable `errors.Is()` checking rather than string matching
- `PopEvents()` pattern on the aggregate is standard and well-known
- Compensating transaction in `HoldSeats` is commented explaining the *why*
- Domain model is tested independently of infrastructure
- Consistent package structure follows Clean Architecture layer naming

**What prevents 10/10:**

- `_ = b.Release()` silently discards an error
- Double `time.Now()` in `Confirm()` (minor but noticeable)
- Validator messages not translated to user-friendly strings
- Handler tests use hand-written mocks; no table-driven tests for the booking service

---

## DDD Implementation — 8.0 / 10

**What earns the score:**

- Booking aggregate root controls all state transitions
- Domain events raised on every state change
- Value objects (`Seat`, `Money`) are immutable by convention
- Repository interfaces in domain layer — correct DIP
- Bounded contexts properly separated (booking vs. movie)
- Factory function `New()` enforces invariants at creation time

**What prevents 10/10:**

- No domain service for cross-aggregate policy (booking limit validation is in application layer)
- `Session` is a DTO, not a domain entity
- No aggregate version field
- `BookingPolicy` (max seats, valid seat IDs) could be a domain service rather than application-layer checks

---

## Clean Architecture — 9.0 / 10

**What earns the score:**

The dependency rule is followed perfectly. No layer reaches inward to bypass its abstraction boundary. The `interfaces/http/apierr` package correctly imports domain error types to perform the mapping — this is the right place for this knowledge. The router configuration is passed as a value object (`RouterConfig`) rather than scattered env vars.

**What prevents 10/10:**

- `AllowedOrigins: []string{"*"}` is hardcoded in `main.go` rather than coming from config
- `uuid` imported in application layer but `crypto/rand` used in domain — minor inconsistency
- Test doubles are hand-written per test file rather than in shared `testutil` package

---

## Documentation — 8.0 / 10

**What earns the score:**

- `CLAUDE.md` is comprehensive: commands, architecture, key invariants, Redis schema, API table
- `docs/RUNNING_THE_APPLICATION.md` covers three setup scenarios with troubleshooting
- Swagger UI served at `/api/v1/docs`
- Inline comments explain non-obvious decisions (RC-01, RC-02, compensating transaction)
- `README.md` not reviewed but `CLAUDE.md` is excellent

**What prevents 10/10:**

- No Architecture Decision Records (ADRs)
- No contribution guide (in progress — see open source prep)
- No baseline load test results in the repo
- Swagger spec not verified to reflect all M9–M12 changes

---

## Production Readiness — 5.0 / 10

**What earns the score:**

- Graceful shutdown
- Non-root containers
- Health checks
- Prometheus metrics
- Structured logging
- Compensating transactions
- Dockerfile and docker-compose for full-stack deployment

**What prevents 10/10:**

- No user authentication
- No rate limiting
- No payment integration
- Single-node Redis and MongoDB
- No circuit breakers
- Seeder uses past dates
- Weak default admin password in docker-compose
- No TLS
- No pagination

---

## How to Reach 10/10

| Gap | Score Impact | Effort |
|---|---|---|
| Add JWT authentication | +2.0 security, +1.5 production | 3–5 days |
| Rate limiting | +2.0 security, +0.5 scalability | 0.5 day |
| Catalog caching in Redis | +1.0 performance | 0.5 day |
| Fix seeder dates | +0.5 production | 1 hour |
| SSE instead of polling | +1.0 scalability | 2 days |
| MongoDB HA + Redis HA | +1.5 production | 2–3 days |
| Payment stub integration | +1.0 production | 2 days |
| ADRs for key decisions | +0.5 documentation | 1 day |
| Fix Content-Type enforcement | +0.5 security | 2 hours |
| Aggregate versioning | +0.5 DDD | 1 day |
