# Production Architecture

_Phase 7 — Production-grade deployment design — 2026-06-09_  
_Builds on: concurrency-review.md (Phase 6), scalability-analysis.md (Phase 0)_

---

## 1. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  INTERNET                                                                    │
└───────────────────────────┬──────────────────────────────────────────────────┘
                            │ HTTPS :443
                ┌───────────▼──────────────┐
                │  CDN / Edge (Cloudflare)  │   static assets, DDoS protection
                └───────────┬──────────────┘
                            │
                ┌───────────▼──────────────┐
                │  Load Balancer (L7)       │   TLS termination, health checks
                │  Nginx / AWS ALB          │   sticky sessions NOT needed
                └───────────┬──────────────┘
                            │
               ┌────────────┼────────────┐
               │            │            │
    ┌──────────▼──┐ ┌───────▼─────┐ ┌───▼──────────┐
    │  API Gateway │ │  API Gateway│ │  API Gateway  │  rate limit, JWT validation,
    │  (Kong)      │ │  (Kong)     │ │  (Kong)       │  request routing, metrics
    └──────┬───────┘ └──────┬──────┘ └───┬───────────┘
           │                │             │
    ┌──────▼──────────────────────────────▼──────────────────┐
    │              Go Backend Pod Pool                        │
    │   ┌──────────┐  ┌──────────┐  ┌──────────┐            │
    │   │  pod-1   │  │  pod-2   │  │  pod-N   │  stateless │
    │   │ :8080    │  │ :8080    │  │ :8080    │            │
    │   └────┬─────┘  └────┬─────┘  └────┬─────┘            │
    └────────┼─────────────┼─────────────┼────────────────────┘
             │             │             │
    ┌────────▼─────────────▼─────────────▼────────────────────┐
    │                  DATA LAYER                               │
    │                                                           │
    │  ┌───────────────────────────┐  ┌──────────────────────┐ │
    │  │  Redis Sentinel Cluster   │  │  MongoDB Replica Set  │ │
    │  │  master + 2 replicas      │  │  primary + 2 secondary│ │
    │  │  (seat locks, sessions)   │  │  (movies, bookings)   │ │
    │  └───────────────────────────┘  └──────────────────────┘ │
    │                                                           │
    │  ┌───────────────────────────┐                           │
    │  │  NATS JetStream           │  async domain events      │
    │  │  (event bus)              │  ReservationConfirmed,    │
    │  └───────────────────────────┘  BookingConfirmed, etc.   │
    └───────────────────────────────────────────────────────────┘
             │
    ┌────────▼──────────────────────────────────────────────────┐
    │                  OBSERVABILITY STACK                       │
    │  Prometheus  Loki  Tempo  Grafana  AlertManager           │
    └───────────────────────────────────────────────────────────┘

    ┌──────────────────────────────────────────────────────────┐
    │  Next.js Frontend                                        │
    │  Vercel / dedicated pod pool                             │
    │  SSR on edge, client polling → API                       │
    └──────────────────────────────────────────────────────────┘
```

---

## 2. Component Selection Rationale

### Load Balancer — Nginx / AWS ALB

**Choice**: Layer-7 load balancer with health check on `GET /health`.

**Why L7 not L4**: L7 enables path-based routing (e.g., `/api/v1/admin/*` → separate backend pool with lower replica count), WebSocket upgrade support for future SSE/WS seat updates, and HTTP/2 multiplexing.

**Why not sticky sessions**: The Go backend is stateless — all session state is in Redis. Round-robin distribution is correct. Sticky sessions would reduce failover effectiveness.

**Health check**:
```
GET /health → 200 {"status":"ok","redis":"ok","mongo":"ok"}
interval: 10s, timeout: 3s, unhealthy_threshold: 2
```

Remove unhealthy pods from rotation immediately. Pod with Redis connection failure returns 503 and is removed within 20 seconds.

---

### API Gateway — Kong

**Responsibility**: Rate limiting, JWT authentication (once Identity context is implemented), request/response logging, circuit breaking, API versioning.

**Why Kong not Nginx**: Kong has first-class plugin support for rate limiting by user ID (not just IP), JWT validation, and Prometheus metrics export. Nginx requires Lua scripting to replicate this.

**Key plugins configured**:

| Plugin | Configuration |
|---|---|
| `rate-limiting` | 100 req/min per IP; 30 hold-requests/min per user_id |
| `request-id` | Inject `X-Request-ID` if absent |
| `prometheus` | Expose metrics at `/metrics` |
| `cors` | Restrict to frontend origin in production |
| `jwt` (Phase 8+) | Validate Bearer token; extract `sub` as user_id |

**Why not build rate limiting in Go**: Kong decouples rate-limit policy from application code. Rules can be updated without redeploying the Go service.

---

### Go Backend — Kubernetes Deployment

**Replicas**: 3 minimum in production (1 can be lost without capacity impact). Horizontal Pod Autoscaler on CPU > 60% or RPS > 500/pod.

**Resource requests**:
```yaml
resources:
  requests: { cpu: "250m", memory: "128Mi" }
  limits:   { cpu: "1000m", memory: "256Mi" }
```

**Why these limits**: The Go backend is CPU-light (mostly I/O wait on Redis/Mongo). 250m CPU handles ~1000 req/s. Memory is bounded because there is no in-process caching — all state is external.

**Graceful shutdown**: Already implemented (`SIGTERM → 10s drain`). Kubernetes `terminationGracePeriodSeconds: 15` ensures in-flight requests complete before pod is killed.

---

### Redis — Sentinel Cluster

**Topology**: 1 master + 2 replicas + 3 sentinel processes.

```
┌─────────────┐     replication     ┌──────────────┐
│ Redis Master │──────────────────► │ Redis Replica │
│ :6379        │                    │ :6380         │
└──────┬───────┘                    └──────┬────────┘
       │                                   │
       │           replication             │
       └──────────────────────────────────►┤
                                    ┌──────▼────────┐
                                    │ Redis Replica  │
                                    │ :6381          │
                                    └───────────────┘

Sentinel (3 instances, quorum=2):
  sentinel-1 :26379
  sentinel-2 :26380
  sentinel-3 :26381
```

**Failover time**: ~5–30 seconds. During failover, `hold` and `confirm` requests return 503. The frontend should display a "system busy" message rather than an error. Clients retry after backoff.

**Go client configuration**:
```go
rdb := goredis.NewFailoverClient(&goredis.FailoverOptions{
    MasterName:       cfg.Redis.MasterName,     // "mymaster"
    SentinelAddrs:    cfg.Redis.SentinelAddrs,  // ["s1:26379","s2:26380","s3:26381"]
    SentinelPassword: cfg.Redis.SentinelPass,
    Password:         cfg.Redis.Password,
    DB:               0,
    PoolSize:         20,
    MinIdleConns:     5,
    ConnMaxIdleTime:  5 * time.Minute,
    ReadTimeout:      2 * time.Second,
    WriteTimeout:     2 * time.Second,
})
```

**Read replicas for seat map queries**: `GetAvailability` can use replica read (slightly stale data is acceptable — the frontend polls every 2s anyway):
```go
rdbReader := goredis.NewFailoverClient(&goredis.FailoverOptions{
    // same sentinel config
    SlaveOnly: true,  // route reads to replica
})
```

**Key expiry notifications** (for expired session cleanup):
```
CONFIG SET notify-keyspace-events "Ex"
```
Subscribe to `__keyevent@0__:expired` to detect session TTL expiry and emit `ReservationExpired` events.

---

### MongoDB — Replica Set

**Topology**: 1 primary + 2 secondaries.

```
┌──────────────────┐
│  Primary         │  all writes
│  :27017          │
└──────┬─────┬─────┘
       │     │ replication (async, <100ms lag typical)
  ┌────▼──┐  └──────────────────┐
  │ Sec-1 │                ┌────▼──┐
  │ :27018│                │ Sec-2 │
  └───────┘                │ :27019│
                           └───────┘
```

**Read preference**: Catalog queries (`ListMovies`, `GetScreening`) use `ReadPreference: secondaryPreferred` — slightly stale data (< 100ms) is acceptable for catalog reads. Booking queries (`FindBySessionID` on confirm path) use primary — must be authoritative.

**Write concern**: `{w: "majority", j: true}` for booking writes (Confirm, Save). Ensures writes survive failover. Slightly higher latency (~5ms) but data is safe.

**Indexes review** (current + additions):

| Collection | Index | Type | Purpose |
|---|---|---|---|
| `bookings` | `session_id` | Unique | FindBySessionID (hot path) |
| `bookings` | `user_id` | Standard | User booking history |
| `bookings` | `showtime_id` | Standard | Showtime availability check |
| `bookings` | `status` | Standard | Filter by status |
| `bookings` | `created_at` | DESC | Default sort |
| `bookings` | `expires_at` + `status` | Compound | Find expired held bookings (TTD-08) |
| `movies` | `_id` | PK | Direct lookup |
| `showtimes` | `_id` | PK | Direct lookup (hot path: every hold) |
| `showtimes` | `movie_id` | Standard | List showtimes for movie |

---

### Event Bus — NATS JetStream

**Why NATS not Kafka**: NATS JetStream is Go-native, has a minimal operational footprint (single binary, ~50MB RAM), and provides at-least-once delivery with consumer groups. For 10k bookings/day, Kafka is operationally excessive.

**Why async events**: The in-process dispatcher (Phase 5) is correct for now. Moving to NATS enables:
- Booking service scales independently from Reservation service
- Event replay for analytics, audit, or recovery
- Future payment service subscribes without changing Reservation code
- Dead-letter queue for failed event handlers

**Event flows**:
```
ReservationService ──publish──► NATS JetStream: "reservations"
                                    │
                         ┌──────────┼──────────────────┐
                         │          │                   │
              ┌──────────▼──┐ ┌─────▼──────┐ ┌────────▼────────┐
              │  Booking    │ │ Analytics  │ │  Notification   │
              │  Consumer   │ │  Consumer  │ │  Consumer       │
              │  (create /  │ │  (future)  │ │  (future email) │
              │   confirm)  │ └────────────┘ └─────────────────┘
              └─────────────┘
```

**NATS stream configuration**:
```go
js.AddStream(&nats.StreamConfig{
    Name:      "RESERVATIONS",
    Subjects:  []string{"reservations.>"},
    Retention: nats.LimitsPolicy,
    MaxAge:    7 * 24 * time.Hour,  // retain 7 days for replay
    Storage:   nats.FileStorage,
    Replicas:  3,  // HA
})
```

**Migration path from in-process dispatcher**: The `events.Dispatcher` interface (Phase 5) is backend-agnostic. Swap `InProcessDispatcher` for `NATSDispatcher` in `main.go` without changing any domain or application code.

---

### Caching Strategy

**What to cache** (in Redis, TTL-based):

| Data | TTL | Key | Invalidation |
|---|---|---|---|
| `ListMovies` response | 60s | `cache:movies:list` | On admin CreateMovie |
| `GetMovie` response | 60s | `cache:movie:{id}` | On admin update |
| `GetScreening` response | 30s | `cache:screening:{id}` | Never changes post-creation |

**What NOT to cache**:
- Seat availability (real-time, changes every second under load)
- User bookings (personalised, must be fresh)
- Session state (already in Redis with TTL)

**Cache-aside pattern** (in `application/catalog/service.go`):
```go
func (s *Service) GetMovie(ctx context.Context, id string) (catalog.Movie, error) {
    if movie, ok := s.cache.Get(ctx, "cache:movie:"+id); ok {
        return movie, nil
    }
    movie, err := s.repo.FindByID(ctx, id)
    if err != nil { return catalog.Movie{}, err }
    s.cache.Set(ctx, "cache:movie:"+id, movie, 60*time.Second)
    return movie, nil
}
```

**Estimated cache impact**: 95% of `GET /movies` traffic served from Redis cache. Reduces MongoDB read load by ~20× for catalog queries.

---

## 3. Horizontal Scaling Strategy

### Go Backend: Linear Horizontal Scaling

The Go backend is **fully stateless** — no shared in-process state. Adding pods increases throughput linearly.

```
1 pod:   ~1 000 req/s  (I/O bound: Redis + Mongo)
3 pods:  ~3 000 req/s
10 pods: ~10 000 req/s (Redis becomes bottleneck at this point)
```

**Kubernetes HPA**:
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
spec:
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target: { type: Utilization, averageUtilization: 60 }
  - type: Pods
    pods:
      metric: { name: http_requests_per_second }
      target: { type: AverageValue, averageValue: "500" }
```

**Scale-out trigger**: RPS > 500/pod OR CPU > 60%.  
**Scale-in delay**: 5 minutes (prevents flapping during flash sale bursts).

### Redis: Write Scaling via Partitioning

Redis master handles ~100k ops/s. Seat map polls are the bottleneck (see scalability-analysis.md).

**Short-term** (current scale): Route seat-map reads to Redis replica (`SlaveOnly: true`). Doubles effective read throughput.

**Medium-term** (10× scale): Shard by screening ID. Screenings are natural shards — all keys for `dune2-hall1-1` go to the same Redis node.

```
Redis node 1: screenings 001–100  (seat:001:*, session:*)
Redis node 2: screenings 101–200
Redis node 3: screenings 201–300
```

**Long-term** (100× scale): Redis Cluster with hash tags. Requires key format change (Phase 6 recommendation: `seat:{screeningID}:seatID`).

### MongoDB: Read Scaling via Secondaries

Secondary-preferred reads for catalog. Primary takes only writes and consistency-critical reads (booking confirm path).

At 10× current scale, add a dedicated analytics replica with `ReadPreference: secondary, TagSets: [{role: analytics}]` to isolate reporting queries from booking traffic.

---

## 4. High Availability & Failover

### Failure Mode Analysis

| Component | Failure | Detection | Recovery | Data Loss |
|---|---|---|---|---|
| Go pod | OOM / panic | LB health check (10s) | Kubernetes restart (<30s) | None (stateless) |
| Redis master | Crash | Sentinel quorum (5s) | Sentinel promotes replica (~30s) | In-flight Lua scripts fail; clients retry |
| Redis replica | Crash | Sentinel (5s) | No impact on writes; read failover | None |
| MongoDB primary | Crash | Replica set election (10s) | Secondary promoted (<30s) | In-flight unacknowledged writes (use `w:majority` to prevent) |
| MongoDB secondary | Crash | No impact | Background resync on restart | None |
| NATS node | Crash | Client reconnect | NATS cluster re-elects leader | None (JetStream persisted) |
| API Gateway | Crash | LB removes instance | Kong clustered; no single point | None |

### Redis Failover Sequence

```
t=0:   Redis master stops responding
t=5:   Sentinel quorum declares master down (3/3 sentinels agree)
t=10:  Sentinel elects new master (replica with smallest replication lag)
t=15:  All sentinels notify clients of new master address
t=20:  go-redis FailoverClient reconnects to new master
t=20+: Requests succeed again
```

**Client behaviour during failover**: go-redis retries failed commands once after reconnect. Hold requests that fail during the 20s window return 503 to the client. The frontend should implement exponential backoff (500ms → 1s → 2s, max 3 retries) and show "System busy, please try again."

### Circuit Breaker Pattern

Wrap Redis and MongoDB calls with a circuit breaker to prevent cascading failures:

```go
// infrastructure/persistence/redis/circuit_breaker.go
// Using sony/gobreaker or manually:

type CircuitBreaker struct {
    failures    int64
    threshold   int64
    openUntil   time.Time
    mu          sync.RWMutex
}

func (cb *CircuitBreaker) Execute(fn func() error) error {
    cb.mu.RLock()
    if time.Now().Before(cb.openUntil) {
        cb.mu.RUnlock()
        return ErrCircuitOpen
    }
    cb.mu.RUnlock()
    err := fn()
    if err != nil {
        atomic.AddInt64(&cb.failures, 1)
        if atomic.LoadInt64(&cb.failures) > cb.threshold {
            cb.mu.Lock()
            cb.openUntil = time.Now().Add(30 * time.Second)
            cb.mu.Unlock()
        }
    }
    return err
}
```

**Thresholds**: 10 failures in 10 seconds → open circuit for 30 seconds.

---

## 5. Distributed Booking Consistency: Saga Pattern

The current design has a dual-write problem: Redis (seat locks) and MongoDB (booking records) are updated in sequence without a transaction. Phase 6 identified RC-01 as a consequence.

### Target: Choreography-Based Saga

A Saga is a sequence of local transactions, each with a compensating transaction that undoes it on failure.

```
Step 1: Reserve seats (Redis Lua NX)
  Compensate: Release seats (Redis Lua DEL)

Step 2: Create booking record (MongoDB insert)
  Compensate: Delete booking record

Step 3: Confirm reservation (Redis Lua PERSIST)
  Compensate: Re-add TTL? (not needed — if step 4 fails, we retry)

Step 4: Update booking status (MongoDB update)
  Compensate: Set status back to held (compensate = retry)
```

**Current event-driven flow (post Phase 5)**:

```
ReserveSeats
  → SeatReservation.New() → SeatsReserved event
  → reservationRepo.Reserve() (Redis Lua) ←─ Saga Step 1
  → dispatcher.Dispatch(SeatsReserved)
      → OnSeatsReserved: bookingRepo.Save(held) ←─ Saga Step 2
        If Save fails: dispatcher.Dispatch(ReservationShouldBeReleased)
                         → reservationRepo.Release() ←─ Compensation Step 1

ConfirmReservation
  → reservationRepo.Confirm() (Redis PERSIST) ←─ Saga Step 3
  → dispatcher.Dispatch(ReservationConfirmed)
      → OnReservationConfirmed: bookingRepo.Update(confirmed) ←─ Saga Step 4
        If Update fails: LOG + retry (idempotent, safe to retry)
```

### Saga State Machine

```
                PENDING
                   │
         ┌─────────┴──────────┐
         │ SeatsReserved       │ SeatsReserveFailed
         ▼                    ▼
    SEATS_LOCKED          FAILED (terminal)
         │
         │ BookingCreated (or)  BookingCreateFailed
         │                          │
         ▼                          ▼
    BOOKING_HELD            COMPENSATING
         │                     (release seats)
         │                          │
    UserConfirms             FAILED_COMPENSATED
         │
         │ ReservationConfirmed
         ▼
    CONFIRMING
         │
         │ BookingConfirmed
         ▼
    CONFIRMED (terminal)

    or at any ACTIVE state:
         │ UserCancels / TTL expires
         ▼
    CANCELLING → CANCELLED (terminal)
```

### Idempotency

Every saga step must be idempotent (safe to retry):
- `Reserve`: Redis NX is idempotent (re-running returns SEAT_TAKEN if already held by same session)
- `Save booking`: Unique index on `session_id` prevents duplicate inserts (returns duplicate key error → treated as success)
- `Confirm`: PERSIST on already-persistent key is a no-op
- `Update confirmed`: `ReplaceOne` with same data = no-op

---

## 6. Observability Stack

### Metrics — Prometheus + Grafana

**Instrumentation** in Go backend (OpenTelemetry SDK):

```go
// Custom metrics to instrument
var (
    reservationDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "reservation_hold_duration_seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"screening_id"},
    )
    reservationConflicts = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "reservation_conflicts_total"},
        []string{"screening_id"},
    )
    activeReservations = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{Name: "active_reservations"},
        []string{"screening_id"},
    )
    redisPoolSize = prometheus.NewGauge(
        prometheus.GaugeOpts{Name: "redis_pool_in_use"},
    )
)
```

**Expose at** `GET /metrics` (add to router, exclude from rate limiter).

**Grafana dashboards**:
- **Booking Flow**: RPS by endpoint, hold/confirm/release rates, conflict rate
- **Latency**: p50/p95/p99 for hold, confirm, seat-map by screening
- **Infrastructure**: Redis pool utilisation, MongoDB connection count, pod CPU/memory
- **Business**: Seats held vs confirmed vs released by screening (real-time occupancy)

### Logging — Loki + Promtail

Current `log/slog` JSON handler writes to stdout. Promtail ships stdout logs to Loki.

**Log fields required on every request**:
```json
{
  "time": "2026-06-09T...",
  "level": "INFO",
  "request_id": "uuid",
  "method": "POST",
  "path": "/api/v1/screenings/dune2-hall1-1/reservations",
  "status": 201,
  "latency_ms": 23,
  "user_id": "user-abc123",
  "screening_id": "dune2-hall1-1",
  "ip": "1.2.3.4"
}
```

**Log levels**:
- `INFO`: every request, major lifecycle events (reservation created, confirmed)
- `WARN`: non-fatal infra errors (MongoDB update failed after Redis confirm)
- `ERROR`: unrecoverable errors, saga compensation failures
- `DEBUG`: disabled in production (enabled via env for troubleshooting)

### Tracing — OpenTelemetry + Tempo

**Instrumentation points**:

```go
// interfaces/http/middleware/tracing.go
func Tracing(tp trace.TracerProvider) gin.HandlerFunc {
    tracer := tp.Tracer("cinebook/http")
    return func(c *gin.Context) {
        ctx, span := tracer.Start(c.Request.Context(),
            fmt.Sprintf("%s %s", c.Request.Method, c.FullPath()),
            trace.WithAttributes(
                semconv.HTTPMethod(c.Request.Method),
                semconv.HTTPURL(c.Request.URL.String()),
            ),
        )
        defer span.End()
        c.Request = c.Request.WithContext(ctx)
        c.Next()
        span.SetAttributes(semconv.HTTPStatusCode(c.Writer.Status()))
    }
}
```

**Child spans** for Redis and MongoDB operations:
```go
// In SeatReservationRepository.Reserve():
ctx, span := tracer.Start(ctx, "redis.ReserveSeats")
defer span.End()
span.SetAttributes(
    attribute.String("screening_id", req.ScreeningID),
    attribute.Int("seat_count", len(req.SeatIDs)),
)
```

**Trace propagation**: `X-Trace-ID` / `traceparent` header passed from API Gateway → Go backend → Redis/Mongo spans. Full request trace visible in Grafana Tempo.

### Alerting — Grafana AlertManager

| Alert | Condition | Severity | Action |
|---|---|---|---|
| `HighErrorRate` | error_rate > 1% for 5m | critical | Page on-call |
| `HighLatency` | p95 hold > 500ms for 5m | warning | Slack |
| `RedisPoolExhausted` | pool_in_use == pool_max for 2m | critical | Page |
| `SagaCompensationFired` | compensation_total > 0 for 10m | critical | Slack + investigate |
| `ReservationConflictSpike` | conflicts/total > 50% for 2m | warning | Potential abuse |
| `PodCountLow` | ready_pods < 2 | critical | Page |

---

## 7. Security Layer

### TLS Everywhere

- External: TLS 1.3 at load balancer (Nginx / ALB), HSTS header
- Internal (service-to-service): mTLS via service mesh (Istio) or at minimum TLS with cert rotation
- Database: TLS for Redis (`tls-cert-file`) and MongoDB (`--tlsMode requireTLS`)

### Authentication (Phase 8+)

JWT-based. API Gateway validates the token signature; Go backend trusts the `sub` claim as `user_id`.

```
Client → API Gateway (validate JWT) → Go Backend (extract sub from token context)
                                                      │
                                              no need to pass user_id
                                              in request body anymore
```

### Secrets Management

No credentials in environment variables in plaintext. Use:
- **Kubernetes Secrets** (base minimum): mounted as files, not env vars
- **HashiCorp Vault** (production): dynamic credentials, auto-rotation for MongoDB and Redis passwords

### Network Policy (Kubernetes)

```yaml
# Only API Gateway pods can reach Go backend pods
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-ingress
spec:
  podSelector:
    matchLabels: { app: cinebook-backend }
  ingress:
  - from:
    - podSelector:
        matchLabels: { app: api-gateway }
    ports:
    - protocol: TCP
      port: 8080
```

Redis and MongoDB are not reachable from outside the cluster.

---

## 8. Deployment Topology

### Kubernetes Namespace Layout

```
namespace: cinebook-prod
  deployment/cinebook-backend   (3–20 pods, HPA)
  deployment/api-gateway-kong   (2 pods, fixed)
  service/cinebook-backend      (ClusterIP)
  service/api-gateway           (LoadBalancer → external LB)

namespace: cinebook-data
  statefulset/redis-master      (1 pod)
  statefulset/redis-replica     (2 pods)
  statefulset/redis-sentinel    (3 pods)
  statefulset/mongodb           (3 pods, replica set)
  statefulset/nats              (3 pods, JetStream cluster)

namespace: cinebook-obs
  deployment/prometheus
  deployment/grafana
  deployment/loki
  deployment/tempo
  deployment/alertmanager
  daemonset/promtail
```

### Docker Images

```dockerfile
# Dockerfile (multi-stage)
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/api ./cmd/api

FROM gcr.io/distroless/static-debian12
COPY --from=builder /bin/api /api
EXPOSE 8080
ENTRYPOINT ["/api"]
```

**Image size**: ~10MB (distroless base + single static binary).

---

## 9. Scaling Tiers

| Tier | Traffic | Go Pods | Redis | MongoDB | Cost/mo (est.) |
|---|---|---|---|---|---|
| Dev | < 10 RPS | 1 | single | single | $50 |
| Staging | < 100 RPS | 2 | single | single | $150 |
| Small prod | < 500 RPS | 3 | sentinel | replica set | $500 |
| Medium prod | < 5 000 RPS | 10 | sentinel | replica set | $1500 |
| Large prod | < 50 000 RPS | 30 | cluster | sharded | $8 000 |

The current codebase (after Phase 5–6 fixes) is ready for **Small prod** without changes. **Medium prod** requires the N+1 Redis fix (Phase 5 M6) and Redis replica reads. **Large prod** requires Redis Cluster and hash tag key refactoring.

---

## 10. What This Architecture Does NOT Include

The following are explicitly out of scope for the current project phase but documented for roadmap planning:

| Capability | When Needed | Approach |
|---|---|---|
| Payment processing | Phase 9+ | Stripe integration in Payment context |
| Email notifications | Phase 9+ | NATS consumer → SendGrid |
| Real-time seat updates | When polling causes issues | WebSocket or SSE from Go backend |
| Search | When catalog > 1000 movies | Elasticsearch / typesense |
| Seat map persistence in Postgres | When analytics needed | Migrate from Redis+Mongo to Postgres |
| Multi-region active-active | When global scale needed | CRDTs for seat state, regional Redis clusters |
| Feature flags | When A/B testing | Unleash or GrowthBook |
| Blue-green deployment | When zero-downtime deploys needed | Kubernetes rolling update already handles this |
