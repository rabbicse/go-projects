# Lessons Learned

Engineering retrospective on the Cinema Booking System project.

---

## What Went Well

### 1. Starting with the Hard Problem

The decision to implement the atomic seat reservation invariant first — before building the API layer, before building the frontend, before adding observability — was the right call. Once the Lua scripts were correct and tested, the rest of the system was wiring. The inverse (build the happy path first, add correctness later) tends to produce systems where the correctness is added as an afterthought and has gaps.

**Takeaway**: Identify the hardest correctness property first. Build and test it in isolation before adding convenience.

---

### 2. Clean Architecture Made Layer Changes Easy

During development, the MongoDB driver was upgraded from v1 to v2. Because the domain layer declares only interfaces and the infrastructure layer implements them, the upgrade was entirely contained within `infrastructure/persistence/mongodb/`. No application or domain code changed. The tests still passed.

**Takeaway**: Dependency inversion pays for itself the first time you need to swap an implementation.

---

### 3. Domain Events Enable Future Extensibility

Adding logging of booking events in `main.go` required zero changes to the domain or application layers. The `Dispatcher.Register()` call in `main.go` was the entire change. If a notification service is added later, it registers its handler — again, zero changes to the booking aggregate.

**Takeaway**: Domain events decouple concerns cleanly. The cost is the infrastructure (dispatcher interface, event types) but the payoff compounds.

---

### 4. `errors.Is()` Chain Is Worth the Ceremony

The `apierr.HTTPStatusFor(err)` switch with `errors.Is()` checks looks verbose. But it caught multiple situations where a wrapped error (`fmt.Errorf("context: %w", domainErr)`) needed to be matched back to its sentinel. The alternative — string matching on `err.Error()` — would have been fragile. Typed errors with proper wrapping is the correct approach.

---

## What I Would Do Differently

### 1. Add Authentication Before Building Booking Logic

User authentication was deferred because the interesting engineering problem was the concurrency model. This left the project with a meaningful gap: `user_id` is trusted from the request body. In hindsight, a simple JWT validation layer (even a stateless one) takes half a day and immediately produces a more realistic system.

**Takeaway**: Auth is not optional for a realistic demo. Build the skeleton first, even if it's a stub.

---

### 2. Use Relative Dates in the Seeder

All five seeded showtimes use `2026-05-20`. The project was started before that date. By launch, all demo shows are in the past. A one-line fix (`time.Now().AddDate(0, 0, N)`) would have made the demo always work on a fresh install.

**Takeaway**: Any hardcoded date will become the past. Use relative times for demo data.

---

### 3. Translate Validator Messages Earlier

Go's `gin/validator` produces messages like `"Key: 'HoldSeatsRequest.SeatIDs' Error:Field validation for 'SeatIDs' failed on the 'min' tag"`. These expose struct internals to API clients. Adding a message translator in the handler layer is mechanical but necessary for a professional-feeling API. It was deferred to a backlog item instead of being done from the start.

**Takeaway**: API error messages are a UX concern, not a "nice to have." Build the translation layer with the first handler.

---

### 4. Rate Limiting Is a Day-One Concern

Rate limiting was not added because it felt like an infrastructure concern separate from the core booking logic. In reality, without rate limiting, the hold endpoint can be abused to block entire halls. It belongs in the API from the first day any endpoint goes live.

**Takeaway**: Rate limiting is not optional for public API endpoints. Add it before anyone uses the system.

---

### 5. The `_ = b.Release()` Error Discard

In `ReleaseBooking`, the domain `Release()` call's error is discarded with `_`. The reasoning was "it can only fail if the booking is not in held status, which we already checked." But that reasoning is not documented, and a future reader will see `_` and wonder if there's a real error being swallowed. Either handle it explicitly or write a comment explaining why it's safe to ignore.

**Takeaway**: `_` for errors should always be accompanied by a comment.

---

## Surprising Discoveries

### Redis TTL Semantics Are Subtle

`TTL` on a key that does not exist returns `-2`. `TTL` on a key that exists but has no expiry returns `-1`. Using `-1` to mean "confirmed" and `-2` to mean "not found" is correct but non-obvious. The Lua `luaRelease` script depends on this distinction. This behavior is documented in Redis but easy to get wrong if you assume "no TTL" means something other than `-1`.

### Gin `c.FullPath()` vs `c.Request.URL.Path` for Prometheus Labels

Using `c.Request.URL.Path` for Prometheus labels creates one time series per unique URL — with UUIDs in path parameters, this creates millions of label values (high cardinality), which causes Prometheus to OOM. `c.FullPath()` returns the route template (e.g., `/api/v1/sessions/:sessionId`) which has fixed cardinality. This distinction matters in production and is easy to miss.

### MongoDB's Partial TTL Index

MongoDB's TTL index can be combined with a `partialFilterExpression` to delete only documents matching a condition. This meant no background cleanup job was needed for expired holds — the database handles it natively. The feature exists but is not widely known.

### Next.js Build-Time vs Runtime Environment Variables

`NEXT_PUBLIC_*` variables in Next.js are baked into the client bundle at build time, not resolved at runtime. For Docker Compose, `NEXT_PUBLIC_API_URL=http://backend:8080` had to be passed as a build argument (`args: {NEXT_PUBLIC_API_URL: http://backend:8080}`) in the `docker-compose.yml`. Passing it as a runtime environment variable has no effect on the bundled rewrites.

---

## Architectural Decisions Validated

| Decision | Validation |
|---|---|
| Lua NX scripts for seat locks | `TestConcurrentHold_ExactlyOneWins`: 10 goroutines, exactly 1 wins |
| Compensating transaction on MongoDB write failure | Covered in application service code, documented in comments |
| Partial TTL index on bookings | Verified via MongoDB `explain()` — index used on TTL background scan |
| `c.FullPath()` for metrics | Prometheus label cardinality verified — fixed set of route templates |
| Non-root Docker containers | Verified `whoami` inside container returns `appuser` |
