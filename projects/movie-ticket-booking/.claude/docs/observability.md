# Observability

_Phase 11 — Metrics, traces, logs, dashboards, alerting — 2026-06-09_  
_Builds on: production-architecture.md (Phase 7), backend-refactor-plan.md (Phase 5)_

---

## 1. Three Pillars

```
                    ┌─────────────────────────────────────────────┐
                    │           OBSERVABILITY STACK               │
                    │                                             │
  Application  ──── │  OpenTelemetry SDK (traces + metrics)      │
  (Go backend) ──── │  slog (structured logs → Loki)             │
                    │                                             │
                    │  ┌──────────┐  ┌──────────┐  ┌─────────┐  │
                    │  │Prometheus│  │  Tempo   │  │  Loki   │  │
                    │  │ metrics  │  │  traces  │  │  logs   │  │
                    │  └────┬─────┘  └────┬─────┘  └────┬────┘  │
                    │       │             │              │       │
                    │       └─────────────┴──────────────┘       │
                    │                    │                        │
                    │              ┌─────▼──────┐                │
                    │              │  Grafana   │                │
                    │              │ dashboards │                │
                    │              └─────┬──────┘                │
                    │                    │                        │
                    │           ┌────────▼───────┐               │
                    │           │  AlertManager  │               │
                    │           └────────────────┘               │
                    └─────────────────────────────────────────────┘
```

**Metrics** (Prometheus): What is happening right now? Aggregated counters, gauges, histograms.  
**Traces** (Tempo): Why is a specific request slow? Span waterfall across service boundaries.  
**Logs** (Loki): What happened in detail for a specific request? Structured JSON records.

The three are linked by `request_id` (correlation) and `trace_id` (OTel context). A Grafana panel showing a slow P99 latency spike links directly to exemplar traces; a trace links to its log lines via the `trace_id` field.

---

## 2. SLIs and SLOs

Service Level Indicators are the measurements. Service Level Objectives are the targets.

### SLIs

| SLI | Measurement | Formula |
|---|---|---|
| **Availability** | HTTP success rate | `(5xx count / total requests) < threshold` |
| **Hold latency** | P99 seat-hold response time | `histogram_quantile(0.99, ...)` |
| **Throughput** | Successful holds per second | `rate(booking_holds_total{result="success"}[1m])` |
| **Error rate** | Application error rate (5xx only) | `rate(http_requests_total{code=~"5.."}[5m])` |
| **Conflict rate** | 409 seat conflicts vs total holds | `booking_seat_conflicts_total / booking_holds_total` |

### SLOs

| SLO | Target | Error Budget (30d) |
|---|---|---|
| API availability | 99.9% | 43.2 min |
| Hold latency P99 | < 100ms | — |
| Hold latency P50 | < 20ms | — |
| Booking confirmation success | > 99% | — |
| Seat map refresh latency P95 | < 50ms | — |

The hold latency SLO is the most architecturally significant. The Lua script path is: Gin handler → BookingService → Redis Lua execution. Redis Lua typically runs in 1–5ms. P99 < 100ms leaves 95ms of budget for network + Go processing.

---

## 3. OpenTelemetry SDK Setup

### 3.1 Dependencies

```go
// backend/go.mod additions
go.opentelemetry.io/otel v1.x
go.opentelemetry.io/otel/trace v1.x
go.opentelemetry.io/otel/sdk v1.x
go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.x
go.opentelemetry.io/otel/exporters/prometheus v1.x
go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin v0.x
github.com/redis/go-redis/extra/redisotel/v9 v9.x
go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/mongo/otelmongo v0.x
```

### 3.2 Bootstrap (`cmd/api/telemetry.go`)

```go
package main

import (
    "context"
    "os"

    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
    "go.opentelemetry.io/otel/exporters/prometheus"
    "go.opentelemetry.io/otel/sdk/metric"
    "go.opentelemetry.io/otel/sdk/resource"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
    semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
    "go.opentelemetry.io/otel/propagation"
)

func initTelemetry(ctx context.Context) (shutdown func(context.Context) error, err error) {
    res, err := resource.New(ctx,
        resource.WithAttributes(
            semconv.ServiceName("cinema-booking"),
            semconv.ServiceVersion(os.Getenv("APP_VERSION")),
            semconv.DeploymentEnvironment(os.Getenv("ENVIRONMENT")),
        ),
    )
    if err != nil {
        return nil, err
    }

    // ── Traces ──────────────────────────────────────────────────────────
    traceExporter, err := otlptracegrpc.New(ctx,
        otlptracegrpc.WithEndpoint(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")), // e.g. tempo:4317
        otlptracegrpc.WithInsecure(),
    )
    if err != nil {
        return nil, err
    }

    tp := sdktrace.NewTracerProvider(
        sdktrace.WithBatcher(traceExporter),
        sdktrace.WithResource(res),
        sdktrace.WithSampler(sdktrace.ParentBased(
            sdktrace.TraceIDRatioBased(samplingRate()), // 1.0 dev, 0.1 prod
        )),
    )
    otel.SetTracerProvider(tp)
    otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
        propagation.TraceContext{},
        propagation.Baggage{},
    ))

    // ── Metrics ─────────────────────────────────────────────────────────
    promExporter, err := prometheus.New()
    if err != nil {
        return nil, err
    }
    mp := metric.NewMeterProvider(
        metric.WithReader(promExporter),
        metric.WithResource(res),
    )
    otel.SetMeterProvider(mp)

    return func(ctx context.Context) error {
        _ = tp.Shutdown(ctx)
        return mp.Shutdown(ctx)
    }, nil
}

func samplingRate() float64 {
    if os.Getenv("ENVIRONMENT") == "production" {
        return 0.1 // 10% in production
    }
    return 1.0 // 100% in development
}
```

### 3.3 Wiring in `cmd/api/main.go`

```go
func main() {
    ctx := context.Background()

    shutdown, err := initTelemetry(ctx)
    if err != nil {
        slog.Error("telemetry init failed", "error", err)
        os.Exit(1)
    }
    defer shutdown(ctx)

    // ... rest of main (config, infra, router, server)
}
```

---

## 4. Instrumentation Points

### 4.1 Gin HTTP Middleware (`interfaces/http/middleware/`)

**Tracing** — use the `otelgin` contrib package:

```go
// middleware/tracing.go
import "go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

func TracingMiddleware(serviceName string) gin.HandlerFunc {
    return otelgin.Middleware(serviceName)
}
```

`otelgin` automatically:
- Starts a server span for each request
- Sets `http.method`, `http.route`, `http.status_code` attributes
- Propagates W3C TraceContext from `traceparent` header

**Metrics** — custom Prometheus middleware:

```go
// middleware/metrics.go
func MetricsMiddleware(reg *prometheus.Registry) gin.HandlerFunc {
    requestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "http_requests_total",
        Help: "Total HTTP requests by method, path, and status code.",
    }, []string{"method", "path", "status_code"})

    requestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
        Name:    "http_request_duration_seconds",
        Help:    "HTTP request duration in seconds.",
        Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
    }, []string{"method", "path", "status_code"})

    requestsInFlight := prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "http_requests_in_flight",
        Help: "Current number of HTTP requests being processed.",
    })

    reg.MustRegister(requestsTotal, requestDuration, requestsInFlight)

    return func(c *gin.Context) {
        requestsInFlight.Inc()
        defer requestsInFlight.Dec()

        start := time.Now()
        c.Next()

        path := c.FullPath() // "/api/v1/screenings/:screeningId" not actual path
        if path == "" {
            path = "unknown" // 404s have no matched route
        }
        code := strconv.Itoa(c.Writer.Status())
        requestsTotal.WithLabelValues(c.Request.Method, path, code).Inc()
        requestDuration.WithLabelValues(c.Request.Method, path, code).
            Observe(time.Since(start).Seconds())
    }
}
```

**Key**: use `c.FullPath()` (template) not `c.Request.URL.Path` (actual). The actual path includes user IDs and screening IDs — thousands of unique label values would destroy Prometheus cardinality.

**Request ID propagation**:

```go
// middleware/request_id.go
const RequestIDHeader = "X-Request-ID"

func RequestIDMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        reqID := c.GetHeader(RequestIDHeader)
        if reqID == "" {
            reqID = "req_" + shortuuid.New()
        }
        c.Set("request_id", reqID)
        c.Header(RequestIDHeader, reqID)

        // Add request_id to the OTel span
        span := trace.SpanFromContext(c.Request.Context())
        span.SetAttributes(attribute.String("request_id", reqID))

        // Add to slog context for log correlation
        ctx := context.WithValue(c.Request.Context(), requestIDKey{}, reqID)
        c.Request = c.Request.WithContext(ctx)
        c.Next()
    }
}
```

**Middleware order** (`router.go`):

```go
r.Use(
    middleware.RequestIDMiddleware(),     // 1st: assign request_id
    middleware.TracingMiddleware("cinema-booking"),  // 2nd: OTel span (has request_id)
    middleware.MetricsMiddleware(promRegistry),      // 3rd: Prometheus
    middleware.LoggingMiddleware(logger),            // 4th: slog (has trace_id + request_id)
    middleware.CORSMiddleware(cfg.CORS),             // 5th
    middleware.RateLimitMiddleware(redisClient),     // 6th
)
```

### 4.2 Redis Client (`infrastructure/persistence/redis/`)

```go
// infrastructure/persistence/redis/client.go
import "github.com/redis/go-redis/extra/redisotel/v9"

func NewRedisClient(cfg config.RedisConfig) (*redis.Client, error) {
    client := redis.NewClient(&redis.Options{
        Addr:     cfg.Address,
        Password: cfg.Password,
        DB:       cfg.DB,
    })

    // Auto-instruments all commands with OTel traces
    if err := redisotel.InstrumentTracing(client); err != nil {
        return nil, err
    }
    // Auto-instruments all commands with OTel metrics
    if err := redisotel.InstrumentMetrics(client); err != nil {
        return nil, err
    }

    return client, nil
}
```

`redisotel` creates child spans for every Redis command under the current OTel context. The span waterfall shows: `BookingService.ReserveSeats` → `redis.Script.Run` (with latency).

### 4.3 MongoDB Client (`infrastructure/persistence/mongodb/`)

```go
// infrastructure/persistence/mongodb/client.go
import "go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/mongo/otelmongo"

func NewMongoClient(ctx context.Context, cfg config.MongoConfig) (*mongo.Client, error) {
    opts := options.Client().
        ApplyURI(cfg.URI).
        SetMonitor(otelmongo.NewMonitor()) // traces all MongoDB commands

    return mongo.Connect(ctx, opts)
}
```

### 4.4 Business Metrics in Service Layer

Business metrics live in the application service, not the infrastructure or handler. They capture domain outcomes, not HTTP outcomes.

```go
// application/booking/metrics.go
type BookingMetrics struct {
    holdsTotal        *prometheus.CounterVec
    confirmationsTotal *prometheus.CounterVec
    releasesTotal     *prometheus.CounterVec
    seatConflicts     prometheus.Counter
    holdDuration      prometheus.Histogram
    revenueCents      prometheus.Counter
}

func NewBookingMetrics(reg *prometheus.Registry) *BookingMetrics {
    m := &BookingMetrics{
        holdsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
            Name: "booking_holds_total",
            Help: "Seat hold attempts by result.",
        }, []string{"result"}), // result: success | seats_unavailable | validation_error | internal_error

        confirmationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
            Name: "booking_confirmations_total",
            Help: "Booking confirmation attempts by result.",
        }, []string{"result"}), // result: success | expired | already_confirmed | internal_error

        releasesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
            Name: "booking_releases_total",
            Help: "Booking release attempts by result.",
        }, []string{"result"}), // result: success | not_found | forbidden

        seatConflicts: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "booking_seat_conflicts_total",
            Help: "Seat conflicts from concurrent hold attempts.",
        }),

        holdDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
            Name:    "booking_hold_duration_seconds",
            Help:    "Time between seat hold and final outcome (confirm/release/expire).",
            Buckets: prometheus.LinearBuckets(0, 60, 11), // 0 to 600s in 60s steps
        }),

        revenueCents: prometheus.NewCounter(prometheus.CounterOpts{
            Name: "booking_revenue_cents_total",
            Help: "Total revenue from confirmed bookings in cents.",
        }),
    }
    reg.MustRegister(
        m.holdsTotal, m.confirmationsTotal, m.releasesTotal,
        m.seatConflicts, m.holdDuration, m.revenueCents,
    )
    return m
}
```

Usage in `BookingService.ReserveSeats`:

```go
func (s *BookingService) ReserveSeats(ctx context.Context, cmd ReserveSeatsCommand) (*SeatReservation, error) {
    res, err := s.seatLockRepo.HoldSeats(ctx, cmd.ScreeningID, cmd.SeatIDs, s.holdTTL)
    if err != nil {
        if errors.Is(err, domain.ErrSeatsUnavailable) {
            s.metrics.holdsTotal.WithLabelValues("seats_unavailable").Inc()
            s.metrics.seatConflicts.Inc()
            return nil, err
        }
        s.metrics.holdsTotal.WithLabelValues("internal_error").Inc()
        return nil, err
    }
    s.metrics.holdsTotal.WithLabelValues("success").Inc()
    return res, nil
}
```

### 4.5 Prometheus Scrape Endpoint

```go
// interfaces/http/router.go
import "github.com/prometheus/client_golang/prometheus/promhttp"

// Separate from /api/v1 — not behind CORS or rate limiting
r.GET("/metrics", gin.WrapH(promhttp.HandlerFor(promRegistry, promhttp.HandlerOpts{
    EnableOpenMetrics: true, // exposes exemplars for trace linking
})))
```

Exemplars link Prometheus histograms to specific Tempo traces. When the P99 spikes, click the exemplar dot in Grafana to jump directly to the slow trace.

---

## 5. Metrics Catalogue

### HTTP Layer

| Metric | Type | Labels | Description |
|---|---|---|---|
| `http_requests_total` | Counter | `method`, `path`, `status_code` | All HTTP requests |
| `http_request_duration_seconds` | Histogram | `method`, `path`, `status_code` | Latency distribution |
| `http_requests_in_flight` | Gauge | — | Concurrent requests |

### Booking Domain

| Metric | Type | Labels | Description |
|---|---|---|---|
| `booking_holds_total` | Counter | `result` | Hold attempts |
| `booking_confirmations_total` | Counter | `result` | Confirm attempts |
| `booking_releases_total` | Counter | `result` | Release attempts |
| `booking_seat_conflicts_total` | Counter | — | Lua lock failures |
| `booking_hold_duration_seconds` | Histogram | — | Hold-to-outcome time |
| `booking_revenue_cents_total` | Counter | — | Confirmed booking revenue |

### Redis Infrastructure

| Metric | Type | Labels | Description |
|---|---|---|---|
| `redis_commands_duration_seconds` | Histogram | `cmd`, `result` | Per-command latency (auto via redisotel) |
| `redis_commands_total` | Counter | `cmd`, `result` | Command count (auto via redisotel) |

### MongoDB Infrastructure

| Metric | Type | Labels | Description |
|---|---|---|---|
| `mongodb_duration_seconds` | Histogram | `command`, `collection` | Query latency (auto via otelmongo) |

### Go Runtime (auto-collected)

| Metric | Description |
|---|---|
| `go_goroutines` | Active goroutines |
| `go_memstats_heap_alloc_bytes` | Heap in use |
| `process_cpu_seconds_total` | CPU usage |
| `go_gc_duration_seconds` | GC pause times |

---

## 6. Distributed Tracing

### 6.1 Trace Hierarchy — Hold Flow

```
POST /api/v1/screenings/{id}/reservations
  span: http.server [duration: ~15ms]
  │   attributes: http.method=POST, http.route=/api/v1/screenings/:screeningId/reservations
  │               http.status_code=201, request_id=req_abc123
  │
  ├─ BookingHandler.ReserveSeats [~14ms]
  │   attributes: user_id=550e..., screening_id=matrix-..., seat_count=2
  │
  └─ BookingService.ReserveSeats [~12ms]
      ├─ SeatLockRepository.HoldSeats [~3ms]
      │   attributes: seat_ids=["A3","A4"], ttl_seconds=600
      │   └─ redis.EVAL (Lua luaHold) [~2ms]
      │       attributes: redis.cmd=eval, db.redis.database_index=0
      │
      └─ BookingRepository.Create [~8ms]
          └─ mongodb.insert (bookings) [~7ms]
              attributes: db.operation=insert, db.mongodb.collection=bookings
```

### 6.2 Trace Hierarchy — Availability Polling

```
GET /api/v1/screenings/{id}/availability
  span: http.server [duration: ~8ms]  (polled every 2s)
  │
  └─ BookingService.GetSeatAvailability [~6ms]
      └─ SeatLockRepository.GetSeatStatuses [~5ms]
          └─ redis.PIPELINE [~4ms]
              attributes: redis.cmd=pipeline, pipeline_size=240
              — no individual command spans inside pipeline (too many)
```

**Note**: For the availability endpoint, individual Redis command spans inside the pipeline would generate 240 child spans per call × polling interval = high trace volume. Suppress individual span creation inside pipeline calls; log the pipeline size as an attribute on the parent span instead.

### 6.3 Span Attributes Catalogue

```go
// domain-specific attributes added to spans manually
attribute.String("screening_id", screeningID)
attribute.String("user_id", userID)
attribute.StringSlice("seat_ids", seatIDs)
attribute.String("reservation_id", reservationID)
attribute.String("booking_id", bookingID)
attribute.String("request_id", requestID)
attribute.Int("seat_count", len(seatIDs))
attribute.Int64("total_cents", totalCents)
```

Add these in service methods, not handlers or repositories. The service layer has full domain context; the handler only has HTTP context; the repository only has storage context.

### 6.4 Adding Custom Spans in Service

```go
func (s *BookingService) ReserveSeats(ctx context.Context, cmd ReserveSeatsCommand) (*SeatReservation, error) {
    ctx, span := s.tracer.Start(ctx, "BookingService.ReserveSeats",
        trace.WithAttributes(
            attribute.String("screening_id", cmd.ScreeningID),
            attribute.String("user_id", cmd.UserID),
            attribute.Int("seat_count", len(cmd.SeatIDs)),
        ),
    )
    defer span.End()

    res, err := s.seatLockRepo.HoldSeats(ctx, cmd.ScreeningID, cmd.SeatIDs, s.holdTTL)
    if err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, err.Error())
        return nil, err
    }
    span.SetAttributes(attribute.String("reservation_id", res.ID))
    return res, nil
}
```

---

## 7. Structured Logging

### 7.1 Approach

The backend already uses `slog`. The goal is to make every log line independently queryable in Loki without needing to know the context.

**Format**: JSON in production (`slog.NewJSONHandler`), text in development (`slog.NewTextHandler`). Set via `LOG_FORMAT=json|text` env var.

```go
// cmd/api/main.go
func newLogger(cfg config.Config) *slog.Logger {
    var handler slog.Handler
    opts := &slog.HandlerOptions{Level: logLevel(cfg.LogLevel)}
    if cfg.LogFormat == "json" {
        handler = slog.NewJSONHandler(os.Stdout, opts)
    } else {
        handler = slog.NewTextHandler(os.Stdout, opts)
    }
    return slog.New(handler)
}
```

### 7.2 Log Fields Catalogue

Every log line should include these fields when available:

| Field | Source | Example |
|---|---|---|
| `time` | auto (slog) | `"2026-06-09T12:03:14.123Z"` |
| `level` | auto (slog) | `"INFO"` |
| `msg` | explicit | `"booking confirmed"` |
| `request_id` | middleware | `"req_abc123"` |
| `trace_id` | OTel context | `"4bf92f3577b34da6a3ce929d0e0e4736"` |
| `span_id` | OTel context | `"00f067aa0ba902b7"` |
| `user_id` | service layer | `"550e8400-..."` |
| `screening_id` | service layer | `"matrix-screen1-..."` |
| `reservation_id` | service layer | `"res_7f3e2a1b"` |
| `booking_id` | service layer | `"bkg_9a1c4e2d"` |
| `duration_ms` | calculated | `14` |
| `error` | on failures | `"seats already held"` |

**Never log**: payment tokens, raw credit card numbers, passwords, admin credentials, full request bodies containing PII.

### 7.3 Request-Scoped Logger

Attach trace_id and request_id to every log in a request's scope:

```go
// middleware/logging.go
func LoggingMiddleware(base *slog.Logger) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        reqID, _ := c.Get("request_id")

        // Extract OTel trace info for log correlation
        span := trace.SpanFromContext(c.Request.Context())
        sc := span.SpanContext()

        // Build a request-scoped logger
        logger := base.With(
            "request_id", reqID,
            "trace_id",   sc.TraceID().String(),
            "span_id",    sc.SpanID().String(),
            "method",     c.Request.Method,
            "path",       c.FullPath(),
            "remote_ip",  c.ClientIP(),
        )

        // Inject into context so handlers can use it
        ctx := context.WithValue(c.Request.Context(), loggerKey{}, logger)
        c.Request = c.Request.WithContext(ctx)

        c.Next()

        statusCode := c.Writer.Status()
        logFn := logger.Info
        if statusCode >= 500 { logFn = logger.Error }
        if statusCode >= 400 { logFn = logger.Warn }

        logFn("http request",
            "status_code",  statusCode,
            "duration_ms",  time.Since(start).Milliseconds(),
            "bytes_written", c.Writer.Size(),
        )
    }
}

// Helper to get logger from context in service layer
func LoggerFromContext(ctx context.Context) *slog.Logger {
    if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
        return l
    }
    return slog.Default()
}
```

### 7.4 Log Level Guide

| Level | When |
|---|---|
| `DEBUG` | Detailed trace of what each function received/returned. Off in production. |
| `INFO` | Normal business events: `"booking confirmed"`, `"reservation created"`, `"seat hold released"` |
| `WARN` | Degraded but operational: seat conflict (expected under load), reservation expired, MongoDB slow query |
| `ERROR` | Unexpected failures requiring attention: MongoDB unavailable, Redis Lua error, compensation failed |

### 7.5 Key Log Events

```go
// Booking service — info events
logger.Info("reservation created",
    "reservation_id", res.ID,
    "screening_id",   cmd.ScreeningID,
    "user_id",        cmd.UserID,
    "seat_ids",       cmd.SeatIDs,
    "expires_at",     res.ExpiresAt,
)

logger.Info("booking confirmed",
    "booking_id",     booking.ID,
    "reservation_id", cmd.ReservationID,
    "total_cents",    booking.TotalCents,
    "duration_ms",    time.Since(heldAt).Milliseconds(),
)

// Warn events
logger.Warn("seat conflict — concurrent hold",
    "screening_id",   screeningID,
    "requested_seats", seatIDs,
    "user_id",        userID,
)

logger.Warn("reservation expired — compensation not needed",
    "reservation_id", reservationID,
)

// Error events — always include the original error
logger.Error("mongodb write failed after redis hold — compensating",
    "reservation_id", res.ID,
    "error",          err,
)

logger.Error("redis compensation failed — seat may be phantom-locked",
    "reservation_id", res.ID,
    "seat_ids",       seatIDs,
    "error",          compensErr,
)
```

The last error ("phantom-locked") is a P0 alert trigger — if compensation fails, a seat is stuck as held until the Redis TTL fires. This should page immediately in production.

---

## 8. Grafana Dashboards

### Dashboard 1: Service Overview

**Panels**:

```
Row 1 — Golden Signals (last 5m)
  ┌────────────────┐ ┌────────────────┐ ┌────────────────┐ ┌────────────────┐
  │  Request Rate  │ │  Error Rate    │ │  P50 Latency   │ │  P99 Latency   │
  │  (req/s)       │ │  (5xx %)       │ │  (ms)          │ │  (ms)          │
  │  stat panel    │ │  stat panel    │ │  stat panel    │ │  stat panel    │
  └────────────────┘ └────────────────┘ └────────────────┘ └────────────────┘

Row 2 — Latency Distribution
  ┌──────────────────────────────────┐ ┌──────────────────────────────────┐
  │  HTTP Latency Heatmap            │ │  Latency by Endpoint (line chart) │
  │  http_request_duration_seconds   │ │  p50, p95, p99 per path           │
  └──────────────────────────────────┘ └──────────────────────────────────┘

Row 3 — Traffic
  ┌──────────────────────────────────┐ ┌──────────────────────────────────┐
  │  Requests by Status Code         │ │  In-Flight Requests               │
  │  (stacked area by 2xx/4xx/5xx)   │ │  (gauge + sparkline)              │
  └──────────────────────────────────┘ └──────────────────────────────────┘
```

**Key Prometheus queries**:

```promql
# Request rate
rate(http_requests_total[5m])

# Error rate
sum(rate(http_requests_total{status_code=~"5.."}[5m]))
  / sum(rate(http_requests_total[5m])) * 100

# P99 latency
histogram_quantile(0.99,
  sum(rate(http_request_duration_seconds_bucket[5m])) by (le, path)
)

# P99 by endpoint (table panel)
histogram_quantile(0.99,
  sum(rate(http_request_duration_seconds_bucket[5m])) by (le, path)
) * 1000   # convert to ms
```

---

### Dashboard 2: Booking Domain

**Panels**:

```
Row 1 — Booking Funnel (last 1h)
  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐
  │ Hold Rate  │ │ Confirm    │ │ Release    │ │ Seat       │
  │ (holds/min)│ │ Rate       │ │ Rate       │ │ Conflicts  │
  └────────────┘ └────────────┘ └────────────┘ └────────────┘

Row 2 — Hold Outcomes
  ┌──────────────────────────────────┐ ┌──────────────────────────────────┐
  │  Hold Results (stacked bar)      │ │  Conflict Rate (%)                │
  │  success | unavailable | error   │ │  conflicts / total holds          │
  └──────────────────────────────────┘ └──────────────────────────────────┘

Row 3 — Revenue
  ┌──────────────────────────────────┐ ┌──────────────────────────────────┐
  │  Confirmed Revenue ($)           │ │  Avg Booking Value ($)            │
  │  booking_revenue_cents_total/100 │ │  revenue / confirmations          │
  └──────────────────────────────────┘ └──────────────────────────────────┘
```

**Key queries**:

```promql
# Hold success rate
rate(booking_holds_total{result="success"}[5m])

# Conflict rate (%)
rate(booking_seat_conflicts_total[5m])
  / rate(booking_holds_total[5m]) * 100

# Revenue per minute
rate(booking_revenue_cents_total[1m]) / 100

# Funnel conversion (confirm / hold)
rate(booking_confirmations_total{result="success"}[1h])
  / rate(booking_holds_total{result="success"}[1h]) * 100
```

---

### Dashboard 3: Infrastructure

**Panels**:

```
Row 1 — Redis
  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
  │ Redis Cmd Rate   │ │ Redis P99 Latency│ │ Redis Errors     │
  └──────────────────┘ └──────────────────┘ └──────────────────┘

Row 2 — MongoDB
  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
  │ Mongo Op Rate    │ │ Mongo P99 Latency│ │ Mongo Errors     │
  └──────────────────┘ └──────────────────┘ └──────────────────┘

Row 3 — Go Runtime
  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
  │ Goroutines       │ │ Heap Alloc (MB)  │ │ GC Pause P99     │
  └──────────────────┘ └──────────────────┘ └──────────────────┘
```

---

## 9. Alerting Rules

### `alerts/booking.yml`

```yaml
groups:
  - name: booking.rules
    rules:

      # ── Availability ─────────────────────────────────────────────────────
      - alert: HighErrorRate
        expr: |
          sum(rate(http_requests_total{status_code=~"5.."}[5m]))
            / sum(rate(http_requests_total[5m])) > 0.01
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High 5xx error rate ({{ $value | humanizePercentage }})"
          description: "Error rate exceeds 1% for 2 minutes. Check logs via trace_id."

      - alert: ServiceDown
        expr: up{job="cinema-booking"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "cinema-booking service is down"

      # ── Latency ──────────────────────────────────────────────────────────
      - alert: HoldLatencyHigh
        expr: |
          histogram_quantile(0.99,
            rate(http_request_duration_seconds_bucket{
              path="/api/v1/screenings/:screeningId/reservations",
              method="POST"
            }[5m])
          ) > 0.1
        for: 3m
        labels:
          severity: warning
        annotations:
          summary: "Seat hold P99 latency > 100ms ({{ $value | humanizeDuration }})"
          description: "SLO breach: P99 hold latency exceeds 100ms. Check Redis Lua execution time."

      - alert: HoldLatencyCritical
        expr: |
          histogram_quantile(0.99,
            rate(http_request_duration_seconds_bucket{
              path="/api/v1/screenings/:screeningId/reservations",
              method="POST"
            }[5m])
          ) > 0.5
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Seat hold P99 latency > 500ms — possible Redis issue"

      # ── Booking Domain ────────────────────────────────────────────────────
      - alert: HighSeatConflictRate
        expr: |
          rate(booking_seat_conflicts_total[5m])
            / rate(booking_holds_total[5m]) > 0.3
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High seat conflict rate ({{ $value | humanizePercentage }})"
          description: "More than 30% of hold attempts are conflicting. Likely a highly popular screening."

      - alert: BookingConfirmationErrors
        expr: |
          rate(booking_confirmations_total{result="internal_error"}[5m]) > 0.1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Booking confirmation errors > 0.1/s"
          description: "MongoDB or compensation failures on confirm path. Check error logs."

      # ── Infrastructure ────────────────────────────────────────────────────
      - alert: RedisDown
        expr: redis_up == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "Redis is unreachable — seat locking unavailable"

      - alert: MongoDBDown
        expr: mongodb_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "MongoDB is unreachable — booking persistence unavailable"

      - alert: RedisHighLatency
        expr: |
          histogram_quantile(0.99,
            rate(redis_commands_duration_seconds_bucket[5m])
          ) > 0.01
        for: 3m
        labels:
          severity: warning
        annotations:
          summary: "Redis P99 command latency > 10ms — Lua scripts may be slow"

      # ── Go Runtime ────────────────────────────────────────────────────────
      - alert: GoroutineLeak
        expr: go_goroutines > 1000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Goroutine count > 1000 — possible goroutine leak"

      - alert: HighMemoryUsage
        expr: go_memstats_heap_alloc_bytes > 500 * 1024 * 1024
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Heap allocation > 500MB"
```

### Alert Routing (`alertmanager.yml`)

```yaml
route:
  receiver: "default"
  group_by: ["alertname", "severity"]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h

  routes:
    - match:
        severity: critical
      receiver: "pagerduty-critical"
      repeat_interval: 1h
    - match:
        severity: warning
      receiver: "slack-warnings"

receivers:
  - name: "default"
    slack_configs:
      - channel: "#cinema-alerts"

  - name: "pagerduty-critical"
    pagerduty_configs:
      - routing_key: "${PAGERDUTY_ROUTING_KEY}"

  - name: "slack-warnings"
    slack_configs:
      - channel: "#cinema-warnings"
        title: "[{{ .Status | toUpper }}] {{ .GroupLabels.alertname }}"
        text: "{{ range .Alerts }}{{ .Annotations.summary }}\n{{ end }}"
```

---

## 10. Docker Compose Setup

Enable the commented-out observability block in `docker-compose.yml`:

```yaml
  # ── Observability ────────────────────────────────────────────────────────
  prometheus:
    image: prom/prometheus:v2.51.0
    volumes:
      - ./observability/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./observability/alerts:/etc/prometheus/alerts:ro
      - prometheus_data:/prometheus
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.retention.time=15d"
      - "--web.enable-remote-write-receiver"
    ports:
      - "9090:9090"
    depends_on:
      - backend

  grafana:
    image: grafana/grafana:10.4.0
    environment:
      GF_SECURITY_ADMIN_PASSWORD: "admin"
      GF_FEATURE_TOGGLES_ENABLE: "traceqlEditor"
    volumes:
      - ./observability/grafana/provisioning:/etc/grafana/provisioning:ro
      - grafana_data:/var/lib/grafana
    ports:
      - "3001:3000"   # 3000 is taken by Next.js frontend
    depends_on:
      - prometheus
      - tempo
      - loki

  tempo:
    image: grafana/tempo:2.4.0
    command: ["-config.file=/etc/tempo.yml"]
    volumes:
      - ./observability/tempo.yml:/etc/tempo.yml:ro
      - tempo_data:/var/tempo
    ports:
      - "4317:4317"   # OTLP gRPC (backend → Tempo)
      - "3200:3200"   # Tempo HTTP API (Grafana → Tempo)

  loki:
    image: grafana/loki:2.9.0
    command: ["-config.file=/etc/loki/config.yml"]
    volumes:
      - ./observability/loki.yml:/etc/loki/config.yml:ro
      - loki_data:/loki
    ports:
      - "3100:3100"

  promtail:
    image: grafana/promtail:2.9.0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./observability/promtail.yml:/etc/promtail/config.yml:ro
    command: ["-config.file=/etc/promtail/config.yml"]
    depends_on:
      - loki

volumes:
  prometheus_data:
  grafana_data:
  tempo_data:
  loki_data:
```

### `observability/prometheus.yml`

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "/etc/prometheus/alerts/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets: ["alertmanager:9093"]

scrape_configs:
  - job_name: "cinema-booking"
    static_configs:
      - targets: ["backend:8080"]
    metrics_path: "/metrics"
```

### `observability/promtail.yml`

```yaml
server:
  http_listen_port: 9080

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: "docker"
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
    relabel_configs:
      - source_labels: ["__meta_docker_container_name"]
        target_label: "container"
      - source_labels: ["__meta_docker_container_label_com_docker_compose_service"]
        target_label: "service"
    pipeline_stages:
      - json:
          expressions:
            level: level
            trace_id: trace_id
            request_id: request_id
      - labels:
          level:
          trace_id:
          request_id:
```

### Grafana Data Source Provisioning (`observability/grafana/provisioning/datasources/datasources.yml`)

```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    url: http://prometheus:9090
    isDefault: true
    jsonData:
      exemplarTraceIdDestinations:
        - name: trace_id
          datasourceUid: tempo    # link exemplars to traces

  - name: Tempo
    uid: tempo
    type: tempo
    url: http://tempo:3200
    jsonData:
      tracesToLogsV2:
        datasourceUid: loki       # link traces to logs via trace_id
        filterByTraceID: true
      lokiSearch:
        datasourceUid: loki

  - name: Loki
    uid: loki
    type: loki
    url: http://loki:3100
    jsonData:
      derivedFields:
        - name: TraceID
          matcherRegex: '"trace_id":"(\w+)"'
          url: "$${__value.raw}"
          datasourceUid: tempo    # click trace_id in Loki → jump to Tempo
```

---

## 11. Environment Variables

New env vars added for observability:

```bash
# backend/.env.example additions
OTEL_EXPORTER_OTLP_ENDPOINT=tempo:4317     # Tempo gRPC endpoint
ENVIRONMENT=development                     # used in OTel resource attributes
APP_VERSION=1.0.0                           # used in OTel resource attributes
LOG_FORMAT=json                             # json | text
LOG_LEVEL=info                              # debug | info | warn | error
OTEL_SAMPLING_RATE=1.0                      # 1.0 dev, 0.1 prod
```

---

## 12. Implementation Checklist (M6 from backend-refactor-plan.md)

| Step | File | Change |
|---|---|---|
| M6.1 | `cmd/api/telemetry.go` | Create OTel bootstrap (tracer + meter provider) |
| M6.2 | `cmd/api/main.go` | Call `initTelemetry()`, defer shutdown |
| M6.3 | `infrastructure/persistence/redis/client.go` | Add `redisotel` tracing + metrics hooks |
| M6.4 | `infrastructure/persistence/mongodb/client.go` | Add `otelmongo` command monitor |
| M6.5 | `interfaces/http/middleware/tracing.go` | Add `otelgin` middleware |
| M6.6 | `interfaces/http/middleware/metrics.go` | Add Prometheus HTTP middleware |
| M6.7 | `interfaces/http/middleware/logging.go` | Add trace_id + request_id to slog context |
| M6.8 | `application/booking/metrics.go` | Create `BookingMetrics` struct |
| M6.9 | `application/booking/service.go` | Record business metrics on outcomes |
| M6.10 | `interfaces/http/router.go` | Add `GET /metrics` endpoint |
| M6.11 | `docker-compose.yml` | Uncomment observability services |
| M6.12 | `observability/` | Create config files (prometheus, loki, tempo, promtail, grafana) |
