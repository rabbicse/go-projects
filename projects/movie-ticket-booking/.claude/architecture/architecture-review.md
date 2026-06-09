# Architecture Review

_Phase 1 — Formal assessment based on Phase 0 analysis — 2026-06-09_

---

## 1. Executive Summary

The project implements Clean Architecture and DDD correctly at the structural level. Layer boundaries are respected, the domain is dependency-free, and the core concurrency mechanism (Redis Lua atomic multi-seat lock) is both correct and well-tested.

The gaps are not architectural philosophy failures — they are **incomplete implementation** of the patterns the project already claims to follow. Specifically:
- Domain aggregates have broken invariants (ID assigned outside aggregate, status never set)
- Application services have fire-and-forget persistence that breaks the unit-of-work expectation
- Infrastructure concerns have leaked into the domain package (`Session`, `SeatStatus`)
- No authentication means the clean user-ownership checks at the service layer are unenforceable

**Verdict**: Strong foundation, incomplete execution. Refactor priority is filling these gaps, not redesigning the architecture.

---

## 2. Dependency Graph

### Current (actual)

```
cmd/api/main.go
    │
    ├── config
    ├── interfaces/http  ──────────────────────────────────────────────────┐
    │       └── handler/ (BookingHandler, MovieHandler, AdminHandler)      │
    │       └── middleware/ (Logger, CORS)                                 │
    │       └── dto/ (request/response structs)                            │
    │                                                                      │
    ├── application/booking (Service)  ◄── interfaces via domain repos     │
    │       └── depends on: domain/booking, domain/movie, domain/shared    │
    │                                                                      │
    ├── application/movie (Service)   ◄── interfaces via domain repos      │
    │       └── depends on: domain/movie                                   │
    │                                                                      │
    ├── domain/booking  (zero external deps) ✅                            │
    ├── domain/movie    (zero external deps) ✅                            │
    ├── domain/shared   (zero external deps) ✅                            │
    │                                                                      │
    ├── infrastructure/redis  ──► domain/booking (implements interface)    │
    └── infrastructure/mongodb ─► domain/booking, domain/movie, shared     │
                                                                           │
    interfaces/http ──────────────────────────────────────────────────────┘
        depends on: application/booking, application/movie
        (correct — no direct infra dependency from handler)
```

**Layer compliance**: ✅ All dependency arrows point inward. Infrastructure depends on domain interfaces, not the reverse.

### Violations Found

```
domain/booking/repository.go:
    Session struct  ←── carries Redis TTL semantics (unix int64 ExpiresAt)
    
domain/booking/seat.go:
    SeatStatus      ←── carries JSON struct tags and HTTP presentation fields
                        (HeldByMe, ExpiresAt *int64 — these are API response concepts)
```

These are **infrastructure/presentation concerns embedded in the domain**. They do not prevent the system from working, but they mean the domain package changes when the Redis data model or HTTP response format changes.

---

## 3. Domain Boundary Assessment

### Bounded Contexts (Current — Implicit)

The code implies two bounded contexts without naming them:

**Catalog Context** (movie package)
- Entities: `Movie` (aggregate root), `Showtime` (entity owned by Movie)
- Value Objects: `shared.Money`
- Repository: `movie.Repository`
- Invariants: Hall overlap detection in `Movie.AddShowtime()`

**Reservation Context** (booking package)
- Entities: `Booking` (aggregate root), `Seat` (value object)
- Ephemeral state: `Session` (Redis session — currently misplaced in domain)
- Repository: `booking.Repository` (MongoDB), `SeatLockRepository` (Redis)
- Invariants: `Confirm()` checks `StatusHeld` and `ExpiresAt`; `Release()` checks `StatusHeld`

**Assessment**: The context split is correct. Movie catalog and booking reservation have different change rates and different team ownership in a real organization. The current split maps well to the problem.

**Gap**: There is no explicit User/Identity context. `user_id` is a plain `string` with no domain object. This is acceptable for the current demo scope but blocks authentication implementation.

### Aggregate Integrity Assessment

**`Booking` aggregate**:
| Invariant | Implemented? | Issue |
|---|---|---|
| Cannot confirm unless held | ✅ `Confirm()` checks `StatusHeld` | — |
| Cannot release unless held | ✅ `Release()` checks `StatusHeld` | — |
| Cannot confirm after expiry | ✅ `ExpiresAt` check in `Confirm()` | — |
| ID is self-assigned | ❌ ID set by service after construction | Breaks aggregate identity contract |
| Status set to Expired | ❌ No `Expire()` method | Expired bookings remain "held" in DB |
| At least one seat required | ✅ `ErrNoSeatsSelected` in `New()` | — |

**`Movie` aggregate**:
| Invariant | Implemented? | Issue |
|---|---|---|
| No hall overlap for showtimes | ✅ `AddShowtime()` checks overlap | Bypassed by `MovieService.CreateShowtime()` |
| Showtime belongs to this movie | ✅ `s.MovieID != m.ID` check | — |

---

## 4. Business Rule Placement Analysis

Business rules should live in the domain. Service-layer rules are valid for orchestration. Handler-layer rules are a smell.

| Rule | Current Location | Correct Location? |
|---|---|---|
| Max seats per session | Handler + Service (duplicated) | Service only |
| Seat ID format validation | Service (loops `booking.NewSeat()`) | Domain (already in `NewSeat()`) |
| Hall overlap validation | Domain (`Movie.AddShowtime()`) but bypassed by service | Domain — needs service to call it |
| Booking status transitions | Domain (`Confirm()`, `Release()`) | ✅ Correct |
| Session expiry check | Domain (`Confirm()` reads `ExpiresAt`) | ✅ Correct |
| UserID ownership check | Service (`session.UserID != userID`) | ✅ Correct for now (pre-auth) |
| Money arithmetic | Domain (`Money.Multiply`, `Money.Add`) | ✅ Correct, but `Add()` panics |

**Finding**: The most serious misplacement is the hall-overlap bypass. `MovieService.CreateShowtime()` skips the aggregate and writes directly to the repository. The admin API can create conflicting showtimes. This is a domain invariant violation.

---

## 5. Concurrency Implementation Review

See `analysis/concurrency-analysis.md` for full detail. Summary verdict:

| Aspect | Grade | Notes |
|---|---|---|
| Atomic multi-seat lock | ✅ A | Lua NX script is correct |
| Rollback on partial failure | ✅ A | Same Lua call, no partial state |
| Confirm atomicity | ✅ A | PERSIST in single Lua call |
| Release atomicity | ✅ A | DEL in single Lua call |
| MongoDB + Redis consistency | ❌ C | No saga / compensating transaction |
| Confirmed seat cleanup | ❌ D | Permanent Redis keys — memory leak |
| Seat-map query efficiency | ❌ D | N+1 round trips per GET |
| Race: TTL expiry vs confirm | ⚠️ B- | Narrow window, acceptable with note |

The Go application code itself is correctly stateless (no shared mutable state, no mutexes needed at the application layer). All concurrency is delegated to Redis — the right choice for a distributed system.

---

## 6. Error Handling Assessment

**Pattern used**: Sentinel errors in domain, wrapping with `fmt.Errorf("%w")` in service, `errors.Is()` unwrapping in handler.

This is the idiomatic Go pattern. Grade: ✅ B+

**Gaps**:
1. No structured error type — all errors are `error` with a message string. The frontend matches on `err.Error()` strings for display. Fragile when error messages change.
2. `Money.Add()` panics instead of returning an error.
3. Fire-and-forget `slog.Warn` for MongoDB failures in `HoldSeats` and `ConfirmBooking` upgrade what should be returned errors into silent failures.

**Recommended error type**:
```go
type AppError struct {
    Code    string  // machine-readable: "SEAT_ALREADY_HELD"
    Message string  // human-readable
    Err     error   // wrapped cause
}
```

---

## 7. Logging Assessment

`log/slog` with JSON handler at INFO level. Middleware logs method, path, status, latency, IP.

**Grade**: B

**Gaps**:
- No request ID — correlated log queries are impossible
- No span/trace ID — no OpenTelemetry integration
- Sensitive config (Redis addr) logged at startup
- No structured fields for domain-level events (e.g., "seat held", "booking confirmed") — only warn-level MongoDB failures logged

---

## 8. Configuration Assessment

`caarlos0/env/v11` with typed struct. Nested config sections. All timeouts configurable.

**Grade**: B-

**Issue**: Default values for Redis and MongoDB point to `192.168.0.50` (developer's home network). Breaks out-of-the-box for every other developer. Should be `localhost`.

**Missing**: `ADMIN_USER`, `ADMIN_PASSWORD` env vars (credentials are hardcoded).

---

## 9. Anti-Patterns Catalogue

| # | Anti-Pattern | Location | Impact |
|---|---|---|---|
| AP-01 | **Fire-and-forget persistence** | `application/booking/service.go:85,113` | Data loss under infrastructure failure |
| AP-02 | **God Component** | `frontend/.../showtimes/page.tsx` | Untestable, unmaintainable |
| AP-03 | **Hardcoded credentials in source** | `interfaces/http/router.go:57` | Security breach |
| AP-04 | **Magic IP defaults in config** | `config/config.go:28-29` | Breaks fresh clones |
| AP-05 | **Domain invariant bypass** | `application/movie/service.go:49-56` | Stale data, data corruption |
| AP-06 | **Presentation struct in domain** | `domain/booking/seat.go:33-38` | Layer violation |
| AP-07 | **Infra concern in domain** | `domain/booking/repository.go:44` | Layer violation |
| AP-08 | **Panic in domain logic** | `domain/shared/money.go:22` | Runtime crash risk |
| AP-09 | **Duplicate validation** | handler + service for maxSeats | Divergence risk |
| AP-10 | **Aggregate ID assigned externally** | `application/booking/service.go:83` | Breaks identity contract |
| AP-11 | **Polling instead of push** | `frontend/SeatGrid.tsx:40` | Wasted resources, scalability cliff |
| AP-12 | **Memory leak** | `luaConfirm` — PERSIST, no cleanup | Redis keyspace grows forever |

---

## 10. Coupling Assessment

### Appropriate Coupling (Expected)
- `interfaces/http/handler` → `application/*` services (by concrete type — acceptable since they're in same module)
- `infrastructure/*` → `domain/*` interfaces (correct inversion)

### Problematic Coupling

| From | To | Type | Severity |
|---|---|---|---|
| `application/booking` | `domain/movie` | Cross-aggregate query | Medium — service fetches showtime to get price/movieID |
| `domain/booking` | Redis semantics | Conceptual (Session struct) | Medium |
| `domain/booking` | HTTP semantics | Conceptual (SeatStatus JSON tags) | Low |
| `BookingHandler` | Business rule (maxSeats) | Logic in handler | Low |

The `BookingService` depending on `movie.Repository` is the most notable cross-boundary coupling. The booking service needs to know the showtime price (to calculate total) and the movieID (to store in booking). This is a common DDD challenge — it can be resolved by passing price and movieID explicitly in the command, or by introducing an anti-corruption layer between contexts.

---

## 11. Frontend Architecture Assessment

| Concern | Current | Target |
|---|---|---|
| Component organisation | Flat `components/` + one-off page components | Feature folders (`features/booking/`, `features/catalog/`) |
| State management | Manual `useState` + `setInterval` | TanStack Query (server state) + `useState` (UI state) |
| Form handling | None (no admin validation) | React Hook Form + Zod |
| Error handling | Try/catch in event handlers | React Error Boundaries + TanStack Query error states |
| Loading states | Plain text "Loading…" | Skeleton components |
| Accessibility | `title` attributes only | Full ARIA labels, keyboard navigation |
| Testing | Zero | Vitest + React Testing Library |

The `ShowtimePage` is a 436-line God Component that mixes:
- Data fetching (`useEffect` for showtime load)
- Business state machine (browse → checkout → paying → confirmed)
- Timer management (hold TTL, payment TTL)
- User identity management
- All UI rendering including inline primitive components

Extracting `useBookingFlow()` custom hook alone would reduce the component to ~150 lines and make the business logic independently testable.

---

## 12. What to Fix First (Prioritised)

### Immediate (before any Phase 2+ work)

These can be fixed in an afternoon without touching architecture:

1. `config.go` — change default IPs to `localhost` (5 min)
2. `router.go` — read admin password from env vars (30 min)
3. `money.go` — return error instead of panic (30 min)

### Phase 2 Blockers (architectural groundwork)

These must be resolved before the domain model can be considered stable:

1. **Move `Session` and `SeatStatus` out of domain** — domain model document (Phase 2) should reflect the corrected domain, not the current leaky one
2. **Fix aggregate ID assignment** — `booking.New()` should generate its own UUID
3. **Fix `CreateShowtime` to use `Movie.AddShowtime()`** — domain model should trust its invariants

### Phase 3+ Blockers (DDD/CQRS design)

1. Introduce proper `User` value object / bounded context to enable authentication
2. Domain events on status transitions (needed for CQRS read models)
3. Structured `AppError` type for machine-readable error codes

---

## 13. Architecture Rating

| Dimension | Grade | Rationale |
|---|---|---|
| Layer separation | B+ | Correct direction, two leakage points in domain |
| Domain model | B | Correct aggregates, incomplete invariant enforcement |
| Concurrency | A- | Lua locks correct; N+1 and no cleanup are B-range |
| Error handling | B | Idiomatic wrapping; fire-and-forget is D |
| Security | D | No auth, hardcoded passwords, CORS wildcard |
| Scalability | C | Single-node datastores, N+1 seat map |
| Testability | B | Good integration tests; frontend untestable |
| Frontend | C | Works for demo; God component, no state management |
| **Overall** | **B-** | Strong foundation, production gaps |
