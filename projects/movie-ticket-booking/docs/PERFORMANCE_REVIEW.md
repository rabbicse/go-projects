# Performance Review

**Date**: 2026-06-10  
**Environment**: macOS, backend on localhost:8080, databases on 192.168.0.50 (~8ms RTT)

---

## Measured Latencies

| Endpoint | Measured | DB Round Trips | Assessment |
|---|---|---|---|
| `GET /api/v1/movies` | 11.3ms | 1 MongoDB query | Good |
| `GET /api/v1/movies/:id` | 11.6ms | 1 MongoDB query | Good |
| `GET /api/v1/showtimes/:id` | 19.8ms | 1 MongoDB query | Good |
| `GET /api/v1/showtimes/:id/seats` | 9.5ms | 2 Redis pipelines | Good |
| `POST .../hold` | 20.8ms | 1 Redis script + 1 MongoDB insert | Good |
| `PUT .../confirm` | 34.0ms | 1 Redis GET + 1 Redis script + 1 MongoDB replace | Acceptable |
| Frontend `/` | 86ms | SSR → backend API | Good |
| Frontend `/showtimes/:id` | 56ms | SSR → backend API | Good |

All measurements include ~8ms network RTT to remote databases. Local database setup would reduce all latencies by ~8–16ms per operation.

---

## What's Already Optimized

### Redis Pipeline in `GetSeatStatuses`

The original implementation would have done N GET + N TTL calls serially (N = number of held seats). The current implementation uses:

1. **SCAN** to collect seat keys (1 round trip)
2. **Pipeline 1**: GET + TTL for all seat keys (1 round trip regardless of N)
3. **Pipeline 2**: GET for unique session keys for HeldByMe resolution (1 round trip)

Total: 3 round trips regardless of seat count vs. O(N) in the naive implementation. For a hall with 200 active holds, this is the difference between ~1,600ms and ~10ms.

### MongoDB Indexes

All query patterns have supporting indexes:

```
bookings: session_id (unique), user_id+created_at (compound), showtime_id, status
movies:   slug (unique), indexed for catalog queries
showtimes: movie_id, start_time
```

The TTL partial index on `bookings.expires_at` auto-expires held/expired documents without an external cleanup job — this is operationally excellent and reduces collection growth.

### Atomic Lua Scripts

The three Redis Lua scripts (`luaHoldSeats`, `luaConfirm`, `luaRelease`) each execute atomically on the Redis server side, eliminating network round trips for multi-key operations. This is the correct approach for Redis-based locking.

### Compensating Transaction

When MongoDB write fails after Redis lock is acquired, the service immediately releases the Redis lock. This prevents seat keys from leaking in Redis with no corresponding MongoDB record.

---

## Optimization Opportunities

### OPT-01 — Cache Movie Catalog (High Impact)

`GET /api/v1/movies` and `GET /api/v1/movies/:id` hit MongoDB on every request. Movie data changes rarely (only via admin API). Adding a Redis cache with a 60-second TTL would eliminate ~99% of MongoDB reads on the critical browse path.

```go
// Pseudocode: in MovieService.ListMovies
const movieListCacheKey = "cache:movies:all"
const cacheTTL = 60 * time.Second

if cached, err := cache.Get(ctx, movieListCacheKey); err == nil {
    return cached, nil
}
movies, err := r.movieRepo.FindAll(ctx)
cache.Set(ctx, movieListCacheKey, movies, cacheTTL)
return movies, nil
```

**Impact**: Eliminates MongoDB load on the most-read endpoint. Reduces P99 from ~20ms to ~2ms.

---

### OPT-02 — Showtime Cache (High Impact)

`GetShowtime` is called on every `HoldSeats` request to fetch the price. This MongoDB query adds ~8–10ms to every hold operation. Caching the showtime document (TTL 5 minutes) would reduce hold latency by ~30%.

---

### OPT-03 — Replace 2-second Polling with SSE (High Impact at Scale)

`SeatGrid` polls every 2 seconds. At 100 users on the same showtime, this is 50 `GET /seats` requests/second to Redis. Server-Sent Events would push state changes on write, reducing polling to a one-time connection.

Current polling cost: `O(users × 0.5/s)` requests.  
SSE cost: `O(1)` write-triggered push per state change.

---

### OPT-04 — `confirm` Reduces to 1 Redis Script Instead of GET + Script

`ConfirmSession` currently does:
1. `GetSession` (1 GET → deserialize → re-serialize)
2. `luaConfirm` (1 script run)

The Lua script could accept the session ID and internally fetch, update, and persist the session in one atomic operation, saving one network round trip. Given `confirm` is already at 34ms and the saving would be ~4ms, this is a low-priority optimization.

---

### OPT-05 — `FindByShowtime` Missing Sort (Low Impact)

`BookingRepository.FindByShowtime` returns documents unsorted. Adding `SetSort(bson.D{{Key: "created_at", Value: -1}})` makes the result deterministic and avoids surprising ordering changes as data grows.

---

### OPT-06 — MongoDB Connection Pool Tuning

The MongoDB client is initialized with default pool settings (100 max connections). Under sustained load:

```go
// In mongodb/client.go, configure pool explicitly:
opts.SetMaxPoolSize(50)         // prevent connection exhaustion
opts.SetMinPoolSize(5)          // warm pool for low-traffic periods
opts.SetMaxConnIdleTime(5 * time.Minute)
```

---

### OPT-07 — HTTP Timeouts Are Present (Good)

`main.go` configures `ReadTimeout` and `WriteTimeout` on the HTTP server. These are read from config. Confirmed present — prevents Slowloris attacks and runaway connections. ✅

---

## Frontend Performance

| Page | Load | Notes |
|---|---|---|
| `/` (movie list) | 86ms | Server-rendered; sequential API call to backend |
| `/movies/:id` | 75ms | Server-rendered |
| `/showtimes/:id` | 56ms | Client-rendered (polling starts after hydration) |

**Improvement**: The movie list page makes a single server-side fetch. With OPT-01 (catalog cache), this drops to sub-10ms backend latency, improving page TTFB to ~15–20ms.

**Next.js `cache: "no-store"`**: All `fetch()` calls in `api.ts` use `cache: "no-store"` which disables Next.js data caching. For the catalog, `revalidate: 60` would enable ISR (incremental static regeneration) and reduce server load by an order of magnitude at the cost of 60-second staleness — acceptable for movie listings.

---

## Summary

The performance baseline is solid for a showcase project. The key wins available with moderate effort are OPT-01 and OPT-02 (catalog caching), which would cut MongoDB load by ~80% and reduce the most common read latencies below 5ms. OPT-03 (SSE) is the architectural improvement that matters most at scale.
