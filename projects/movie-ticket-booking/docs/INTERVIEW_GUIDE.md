# Interview Guide

Preparation guide for discussing this project in technical interviews.

---

## The 60-Second Project Pitch

> "I built a full-stack cinema seat reservation system in Go and Next.js. The interesting engineering problem is the concurrency challenge: multiple users simultaneously selecting seats from a finite pool with a 10-minute hold window. I solved this with atomic Redis Lua scripts that either lock all requested seats in one round trip or automatically roll back any partial locks — the same pattern used in production ticket booking systems. The backend follows Clean Architecture with DDD, and the frontend polls a real-time seat map that distinguishes your own holds from other users' holds."

---

## Anticipated Interview Questions

### System Design

**Q: How do you prevent two users from booking the same seat?**

A: The key is atomicity. A naive approach reads seat availability, checks if seats are free, then writes the lock — but this has a race window. Instead, I use a Redis Lua script that sets all seat keys with `SET NX EX` in a single atomic loop. If any seat is already taken, the script deletes all previously set keys in the same execution and returns an error. Redis is single-threaded, so no other command can interleave between iterations of the loop. This gives all-or-nothing semantics across multiple seats in one network round trip.

**Q: What happens if the user closes the browser without confirming?**

A: Two mechanisms handle this. The Redis seat keys have a TTL set at hold time. When the TTL fires, the keys are automatically deleted, freeing the seats. Additionally, the MongoDB booking document has an `expires_at` field with a partial TTL index that auto-deletes held and expired documents after the TTL passes. No external cleanup job or scheduled task is needed.

**Q: What if MongoDB goes down after Redis locks the seats?**

A: I handle this with a compensating transaction. In `HoldSeats`, after acquiring the Redis lock but before returning to the client, I write the booking record to MongoDB. If that write fails, I immediately call `ReleaseSession` to delete the Redis keys. If the release itself fails (which would mean Redis is also down), I log a critical alert with the session ID for manual cleanup. The seat will naturally expire via Redis TTL anyway, but manual cleanup may be needed for the Redis record specifically.

**Q: How does the real-time seat map work without WebSockets?**

A: The frontend polls `GET /showtimes/:id/seats` every 2 seconds. The backend responds with current seat states from Redis. This is straightforward but creates O(users) read load. The correct long-term solution is Server-Sent Events: publish seat changes to a Redis pub/sub channel, have SSE connections subscribe to that channel, and push only diffs to clients. I documented this as the next scalability improvement.

**Q: Walk me through what happens when a user clicks "Hold Seats".**

A:
1. Frontend sends `POST /showtimes/{id}/hold` with `user_id` and `seat_ids` array.
2. Handler validates the request (seat count ≤ max, IDs not empty).
3. Application service fetches the showtime from MongoDB to get the price.
4. Service generates a UUID session ID.
5. Service calls `SeatLockRepository.HoldSeats` which runs the Lua NX script.
6. If successful, service creates a `Booking` aggregate, calls `booking.New()`.
7. Service saves the booking to MongoDB. On failure, releases Redis keys (compensating transaction).
8. Service dispatches domain events (BookingCreated).
9. Handler returns 201 with session ID and expiry time.
10. Frontend stores the session ID and starts a 10-minute countdown.

---

### Architecture

**Q: Why Clean Architecture? Isn't it over-engineered for this?**

A: For a project this size, it might be. But the goal was to demonstrate the pattern correctly, not to choose it pragmatically. The specific benefit here is testability: the domain layer (booking invariants, state machines) can be tested with zero database setup because it has no external dependencies. The application layer can be tested against mock repository interfaces. In a real team context, I'd make the same choice only if the codebase was expected to grow to the point where protecting layer boundaries was worth the ceremony.

**Q: What's DDD and why is Booking the aggregate root?**

A: Domain-Driven Design is about organizing code around the business domain rather than technical concerns. An aggregate root is a cluster of objects treated as a unit for data changes — all changes go through the root to enforce invariants. Booking is the root because:
- It owns Seats (which are value objects — they have no identity outside a booking)
- All state transitions (hold → confirmed → released) must be guarded (can't go from released to confirmed)
- It accumulates domain events that record what happened
If I let external code directly set `booking.Status = "confirmed"`, I'd lose the invariant checks in `Confirm()`.

**Q: What are domain events and why emit them?**

A: Domain events record facts that happened in the domain. `BookingConfirmed` says "this booking was confirmed at this time for this user." Today I use them for logging only. But the same events could trigger:
- Email notifications (send confirmation when `BookingConfirmed` arrives)
- Analytics (track revenue when `BookingConfirmed` fires)
- Seat inventory updates (decrement availability when `BookingCreated` fires)
The advantage: the booking aggregate doesn't know about email or analytics. It just says "this happened." Consumers decide what to do with it.

---

### Go-Specific

**Q: Why use Redis Lua scripts instead of Redlock or WATCH/MULTI/EXEC?**

A: Redlock is for distributed locks across multiple Redis instances — overkill for a single-instance seat lock. `WATCH/MULTI/EXEC` optimistic locking works but requires the client to retry on CAS failure, adding latency and complexity. Lua scripts run atomically on the server — no network round trips between check and set, no retry logic in the client. The tradeoff is that Lua scripts are harder to debug and test. I mitigated this by keeping them minimal and well-commented.

**Q: How is the error handling structured?**

A: Domain errors are typed sentinel values (`var ErrSeatAlreadyHeld = errors.New(...)`). Application code wraps these with `fmt.Errorf("context: %w", err)`. The HTTP layer calls `apierr.HTTPStatusFor(err)` which uses `errors.Is()` to match wrapped errors back to their sentinel and select the appropriate HTTP status code and error code string. Unknown errors default to 500 with a generic message — no internal details leak to clients.

---

### Behavioral

**Q: What would you do differently if starting over?**

A:
1. **Add authentication first.** I built the booking invariant first (which was the interesting problem), but in a real product, auth is table stakes. The `user_id` being trust-on-first-use is a meaningful gap.
2. **Use `time.Now()` once in `Confirm()`.** I noticed a double call — not a real bug, but sloppy.
3. **Translate validator error messages.** Raw `gin/validator` messages expose struct field paths. Should have added a message translator in the handler layer from the start.
4. **Seed with relative dates.** `2026-05-20` is hardcoded. On day one after that date, all demo data is in the past.

**Q: What's the most complex part of this codebase?**

A: The `GetSeatStatuses` method in `seat_lock_repository.go`. It goes from N serial Redis calls (N+1 problem) to 3 pipeline round trips, but doing so requires SCAN → pipeline GET+TTL → collect unique session IDs → pipeline session GET → resolve HeldByMe. The logic is correct but the pipeline handling with error-per-command semantics is easy to get wrong. I added detailed inline comments explaining each step.
