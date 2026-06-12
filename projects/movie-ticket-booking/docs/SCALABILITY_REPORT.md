# Scalability Report

**Date**: 2026-06-10  
**System**: Cinema Booking System

---

## Architecture Under Load

```
Browser → Next.js (SSR+Proxy) → Go/Gin → Redis (atomic locks)
                                       → MongoDB (persistence)
```

The critical path for a seat hold is:
1. Gin handler receives request (~0.1ms)
2. Redis Lua NX script for N seats + session write (1 round trip, ~1ms LAN / ~8ms remote)
3. MongoDB InsertOne for booking record (~5ms LAN / ~20ms remote)
4. HTTP response

Total: **~6ms local / ~30ms remote** — fast enough for sustained load.

---

## Load Tiers

### Tier 1 — 1,000 Concurrent Users

**Assessment**: Handles comfortably with current single-instance architecture.

- Go's goroutine scheduler handles thousands of concurrent HTTP connections with minimal overhead (~4KB stack per goroutine).
- Redis single-threaded command execution serializes seat locks correctly at this scale.
- MongoDB single node handles ~5,000 writes/second; 1,000 concurrent users generating booking operations is well within capacity.
- Prometheus metrics `http_requests_in_flight` will show steady state ~50–100 in-flight at 1,000 concurrent users assuming 50ms average response time.

**Bottleneck**: None at this tier. The system will handle 1,000 concurrent users on a single backend instance and single-node databases.

---

### Tier 2 — 10,000 Concurrent Users

**Assessment**: Requires horizontal scaling of the backend and Redis configuration changes.

**Identified bottlenecks**:

1. **Single Redis node**: All seat lock operations serialize through one Redis instance. At 10,000 users attempting to hold seats simultaneously, Redis CPU becomes the bottleneck for the NX script. A single Redis instance handles ~100,000 simple GET/SET commands/second, but Lua scripts are slower (~30,000–50,000/second). Peak hold throughput: ~5,000–10,000 holds/second — adequate but leaves little headroom.

2. **MongoDB write throughput**: 10,000 concurrent users generating insert/update operations will stress a single MongoDB node. Replica sets with write concern `majority` reduce throughput by ~40%.

3. **Go backend memory**: At 10,000 concurrent requests × ~64KB (request body + response buffer + goroutine stack + allocations), memory pressure reaches ~640MB. Manageable on a single instance but should be monitored.

4. **Seat map polling**: Every user polls `GET /showtimes/:id/seats` every 2 seconds. At 10,000 users on the same showtime, this is 5,000 reads/second to Redis SCAN + pipeline. Redis SCAN is O(N) where N is the keyspace size — with 200 seats this is bounded but still 5,000 concurrent SCAN operations is non-trivial.

**Scaling actions required**:

| Action | Impact |
|---|---|
| Deploy 3–5 backend instances behind a load balancer | Distributes CPU/memory load |
| Redis Sentinel (HA) or Redis Cluster | Eliminates single point of failure |
| MongoDB replica set (3 nodes) | Adds read replicas for non-critical queries |
| Cache `GET /movies` and `GET /showtimes/:id` in Redis | Eliminates MongoDB reads for catalog data |
| Reduce seat map polling to 5s with Server-Sent Events fallback | 60% reduction in Redis SCAN load |

---

### Tier 3 — 100,000 Concurrent Users

**Assessment**: Requires significant architectural changes. Current design will not scale to this tier without re-engineering several components.

**Critical bottlenecks**:

1. **Redis Lua script throughput**: At 100,000 users, even distributed across 10 backend instances, the Redis seat lock becomes the critical path. Redis single-threaded Lua execution caps at ~50,000 scripts/second. Seat hold requests would queue behind the Redis event loop.

   *Solution*: Shard seat locks by showtime ID. With Redis Cluster (16,384 slots), showtimes hash to different nodes. Each node handles its showtime's seat locks independently, linearly scaling throughput.

2. **Seat map polling DoS**: 100,000 users × one poll every 2 seconds = 50,000 requests/second to a single showtime's seat map. This is unsustainable with SCAN-based implementation.

   *Solution*: Replace polling with WebSockets or Server-Sent Events. Publish seat state changes to a Redis pub/sub channel. Clients subscribe to `seat-updates:{showtimeID}`. Backend pushes diffs rather than full scans.

3. **MongoDB write amplification**: Every hold creates a MongoDB document. 100,000 holds/second × ~2KB document = 200MB/second write throughput. MongoDB sharding by `showtime_id` is required.

4. **Stateless backend assumption**: The current design is stateless (no in-memory session state), which is correct for horizontal scaling. However, the `AllowedOrigins: []string{"*"}` and the lack of a proper auth layer mean each backend instance accepts unauthenticated requests — the attack surface scales with instance count.

5. **N+1 showtime load on movie list**: `GET /api/v1/movies` returns all movies with all showtimes embedded. At 100,000 concurrent users, this endpoint generates significant MongoDB cursor load. Caching this response in Redis with a 30-second TTL would eliminate ~99% of that load.

**Required architecture changes for 100K tier**:

```
CDN (static assets, movie list cache)
  ↓
Load Balancer (HAProxy / ALB)
  ↓
Backend instances × 10–20 (stateless Go services)
  ↓                    ↓
Redis Cluster ×3    MongoDB Sharded ×3
(seat locks)        (bookings, movies)
  ↓
Message Queue (Kafka / NATS)
  ↓
Event consumers (notifications, analytics, payment)
```

---

## Scaling Recommendations Summary

| Recommendation | Tier | Effort | Priority |
|---|---|---|---|
| Horizontal backend scale behind load balancer | 10K | Low (already stateless) | High |
| Redis Sentinel for HA | 10K | Medium | High |
| MongoDB replica set with read replicas | 10K | Medium | High |
| Cache movie/showtime catalog in Redis (30s TTL) | 10K | Low | High |
| Replace seat polling with SSE/WebSockets | 10K | High | Medium |
| Redis Cluster (shard by showtime) | 100K | High | Required |
| MongoDB sharding by showtime_id | 100K | High | Required |
| CDN for static Next.js assets | 10K | Low | Medium |
| Async event processing (Kafka/NATS) | 10K | High | Medium |
| Connection pooling config for MongoDB | 1K | Low | Quick win |

---

## Current Single-Instance Theoretical Limits

Based on measured latencies and Go's concurrency model:

| Metric | Estimated Limit |
|---|---|
| Requests/second (mixed workload) | ~3,000 rps |
| Concurrent connections | ~10,000 |
| Seat holds/second | ~500/s (Redis-limited) |
| Seat map reads/second | ~2,000/s (SCAN-limited) |
| MongoDB writes/second | ~2,000/s |

These numbers assume local databases. With remote databases (current dev setup at 192.168.0.50), each adds the RTT penalty (~8ms per operation), reducing throughput proportionally.
