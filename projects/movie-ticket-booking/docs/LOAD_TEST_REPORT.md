# Load Test Report & SLO Definitions

*Applies: test-master skill (performance testing), sre-engineer skill (SLI/SLO, error budgets, multiwindow alerting)*

---

## Prerequisites

```bash
# Install k6 (macOS)
brew install k6

# Or via Docker
docker run -i grafana/k6 run - < load-tests/booking.js
```

> **Status:** k6 not installed in the current environment. This document defines the test design, SLO targets, and expected result bands. Re-run after installing k6 with a live stack.

---

## Test Scenarios

The test suite in `load-tests/booking.js` covers four scenarios. Run via the `SCENARIO` env var:

```bash
cd /path/to/movie-ticket-booking

# 1. Smoke — sanity check (1 VU, 10s)
make load-test-smoke

# 2. Normal load (50 VUs ramp, 2 min)
make load-test

# 3. Spike — burst (500 VUs, 30s)
make load-test-spike

# 4. Concurrent hold — 500 VUs racing the SAME seats (Redis NX lock test)
make load-test-concurrent
```

### Scenario Details

| Scenario | VUs | Duration | Goal |
|---|---|---|---|
| `smoke` | 1 | 10s | Confirm stack is up, endpoints return 2xx |
| `load` | 0→50→0 | 2m total | Baseline latency & throughput under typical traffic |
| `spike` | 0→500→0 | ~1m | Validate graceful degradation under 10× normal load |
| `concurrent_hold` | 500 constant | 30s | Prove Redis NX lock: only 1 winner per seat |

### Flow Per Virtual User

```
1. POST /api/v1/showtimes/{id}/hold         → expect 201 or 409
2. sleep(0.5–1.5s)                          → simulate user reviewing
3. 80%: PUT /api/v1/sessions/{id}/confirm   → expect 200
   20%: DELETE /api/v1/sessions/{id}        → expect 200 (cancel)
```

---

## Thresholds (from `load-tests/booking.js`)

```javascript
thresholds: {
  http_req_duration:   ['p(95)<500', 'p(99)<1000'],  // ms
  hold_error_rate:     ['rate<0.01'],   // <1% non-409 errors on hold
  confirm_error_rate:  ['rate<0.005'],  // <0.5% errors on confirm
}
```

409 Conflict responses on `/hold` are **not counted as errors** — they are correct behaviour under concurrent load (seat already taken). Only unexpected 5xx / network failures increment `hold_error_rate`.

---

## SLI / SLO Definitions

*Using sre-engineer skill: define quantitative SLOs with user-impact justification and calculate error budgets.*

### SLI Definitions

| SLI | Measurement | Numerator | Denominator |
|---|---|---|---|
| **Availability** | Ratio of successful requests | `http_requests_total{status!~"5.."}` | `http_requests_total` |
| **Hold latency** | p95 of `/hold` endpoint duration | — | `http_request_duration_seconds{handler="hold"}` |
| **Confirm latency** | p95 of `/confirm` endpoint duration | — | `http_request_duration_seconds{handler="confirm"}` |
| **Seat map freshness** | p95 of `/seats` response time | — | `http_request_duration_seconds{handler="seatmap"}` |
| **Concurrency correctness** | Fraction of concurrent holds that correctly produce exactly-one-winner | — | verified in `TestConcurrentHold_ExactlyOneWins` |

### SLO Targets

| SLO | Target | Window | Justification |
|---|---|---|---|
| Availability | 99.5% | 30-day rolling | Acceptable for portfolio demo; production target would be 99.9% |
| Hold p95 latency | < 200ms | 5-min rolling | Human perception threshold for "instant" click response |
| Confirm p95 latency | < 300ms | 5-min rolling | Payment confirmation should feel snappy |
| Seat map p95 latency | < 150ms | 5-min rolling | Polled every 2s; must not crowd out booking requests |
| Concurrency correctness | 100% | Always | Any double-booking is a critical defect — no error budget |

### Error Budget Calculation

```
# Availability SLO = 99.5%  →  error budget = 0.5% of requests
# Monthly request estimate (50 RPS × 2,629,800s/month) = 131,490,000 requests
# Error budget = 0.005 × 131,490,000 = 657,450 failed requests/month

# Equivalent downtime:
# (1 - 0.995) × 30 days × 24h × 60min = 216 minutes of full downtime/month
```

---

## Expected Results by Scenario

### Smoke

| Metric | Expected |
|---|---|
| All endpoints | HTTP 2xx |
| Hold latency p95 | < 50ms (local stack, no load) |
| Errors | 0 |

### Normal Load (50 VUs)

| Metric | Expected | Pass threshold |
|---|---|---|
| Hold p95 | 80–150ms | < 500ms ✓ |
| Confirm p95 | 60–120ms | < 500ms ✓ |
| Hold error rate | ~0% | < 1% ✓ |
| RPS (hold + confirm) | ~80–100 req/s | — |
| 409 rate on hold | 5–15% | not counted as error |

### Spike (500 VUs)

| Metric | Expected | Pass threshold |
|---|---|---|
| Hold p95 | 300–500ms | < 500ms — borderline |
| Hold p99 | 700–1000ms | < 1000ms — borderline |
| Hold error rate | < 1% (Redis handles NX well) | < 1% ✓ |
| 409 rate | 40–60% (many seats contested) | not counted as error |
| Memory (Redis) | < 50MB | — |

The spike scenario deliberately pushes to the boundary. If p99 exceeds 1000ms, investigate Redis single-thread saturation or connection pool exhaustion before declaring an SLO breach.

### Concurrent Hold (500 VUs, same seats)

| Metric | Expected |
|---|---|
| Hold successes for seat A1 | **1** (exactly) |
| Hold failures for seat A1 | 499 (ErrSeatAlreadyHeld → 409) |
| Double-booking incidents | **0** |
| Redis `luaHoldSeats` atomicity | Confirmed |

This is the most important scenario. A single double-booking result constitutes a critical failure requiring immediate investigation of the Lua script or Redis configuration.

---

## Prometheus SLO Alerting Rules

*Using sre-engineer skill: multiwindow burn-rate alerting.*

Save to `monitoring/prometheus-rules/booking-slo.yaml`:

```yaml
groups:
  - name: booking_slo_availability
    rules:
      # Fast burn: consumes 2% error budget in 1 hour (14.4x normal burn rate)
      - alert: BookingHighErrorBudgetBurn
        expr: |
          (
            sum(rate(http_requests_total{status=~"5.."}[1h]))
            /
            sum(rate(http_requests_total[1h]))
          ) > 0.072
          and
          (
            sum(rate(http_requests_total{status=~"5.."}[5m]))
            /
            sum(rate(http_requests_total[5m]))
          ) > 0.072
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Booking API burning error budget at 14.4x rate"
          runbook: "Check backend logs: make logs | grep ERROR"

      # Slow burn: sustained 1x budget consumption over 6 hours
      - alert: BookingSlowErrorBudgetBurn
        expr: |
          (
            sum(rate(http_requests_total{status=~"5.."}[6h]))
            /
            sum(rate(http_requests_total[6h]))
          ) > 0.005
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Booking API consuming error budget at sustained rate"

  - name: booking_slo_latency
    rules:
      - alert: BookingHoldLatencyHigh
        expr: |
          histogram_quantile(0.95,
            sum(rate(http_request_duration_seconds_bucket{handler="hold"}[5m])) by (le)
          ) > 0.200
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Hold endpoint p95 latency > 200ms SLO"

      - alert: BookingConfirmLatencyHigh
        expr: |
          histogram_quantile(0.95,
            sum(rate(http_request_duration_seconds_bucket{handler="confirm"}[5m])) by (le)
          ) > 0.300
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Confirm endpoint p95 latency > 300ms SLO"
```

---

## Golden Signal Queries (Grafana / PromQL)

```promql
# Latency — hold endpoint p50/p95/p99
histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket{handler="hold"}[5m])) by (le))

# Traffic — requests per second by handler
sum(rate(http_requests_total[5m])) by (handler)

# Errors — 5xx rate
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m]))

# Saturation — Redis command latency (leading indicator)
histogram_quantile(0.99, sum(rate(redis_command_duration_seconds_bucket[5m])) by (le, cmd))

# Booking funnel — hold → confirm conversion rate
sum(rate(http_requests_total{handler="confirm",status="200"}[5m]))
/
sum(rate(http_requests_total{handler="hold",status="201"}[5m]))
```

---

## Capacity Model

Based on the Lua script design and Redis single-threaded execution:

| Bottleneck | Estimated limit | Notes |
|---|---|---|
| Redis NX throughput | ~100k ops/sec | Single-thread; `luaHoldSeats` is ~N+2 ops for N seats |
| Hold throughput (4 seats) | ~16k holds/sec | (100k / 6 ops per hold) |
| Gin HTTP throughput | ~20k req/s | Benchmark on M-series Mac; scales with CPU |
| MongoDB write throughput | ~5k writes/sec | Bottleneck at high booking volume |

For the demo scale (50–500 VUs), all limits are far from being reached. The stack should handle 500 concurrent users on a single-node deployment without horizontal scaling.

---

## How to Interpret Results

After running `make load-test`, the summary is saved to `load-tests/results/summary.json`:

```json
{
  "scenario": "load",
  "metrics": {
    "http_req_duration_p95": 142.3,
    "http_req_duration_p99": 287.6,
    "hold_error_rate": 0.0,
    "confirm_error_rate": 0.0,
    "total_requests": 12450,
    "rps": 103.7
  }
}
```

**Green:** `hold_error_rate = 0`, p95 < 500ms, p99 < 1000ms  
**Yellow:** p95 > 200ms (latency SLO breach, investigate Redis/MongoDB)  
**Red:** `hold_error_rate > 0.01` (5xx responses on hold — check logs immediately)  
**Critical:** Any double-booking detected in `concurrent_hold` scenario

---

## Regression Tests Covering Concurrency

The Go integration test suite validates the correctness invariants without k6:

| Test | File | What it proves |
|---|---|---|
| `TestConcurrentHold_ExactlyOneWins` | `redis_seat_lock_test.go` | 10k goroutines → exactly 1 winner |
| `TestSeatLock_DuplicateHoldFails` | `redis_seat_lock_test.go` | Second hold on same seat returns `ErrSeatAlreadyHeld` |
| `TestSeatLock_Release` | `redis_seat_lock_test.go` | Released seat is immediately re-holdable |
| `TestHoldSeats_CompensatingTransaction` | `service_test.go` | MongoDB failure triggers Redis rollback |
| `TestConfirmBooking_WrongUser` | `service_test.go` | Session ownership enforced |

Run with: `make test-integration` (requires Docker for testcontainers-go).
