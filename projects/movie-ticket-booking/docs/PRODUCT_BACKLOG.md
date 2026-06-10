# Product Backlog

Derived from the Application Verification & Product Review Phase (2026-06-10). Items are ordered by priority within each category.

---

## Critical

| ID | Title | Finding | Notes |
|---|---|---|---|
| B-01 | Fix seeded showtime dates | F-01 | Seeder hardcodes `2026-05-20`. All demo showtimes are in the past. Replace with `time.Now().AddDate(0, 0, N)` so the app is usable immediately on first boot. |
| B-02 | Validate Content-Type on POST endpoints | F-03 | Gin silently falls back to form parsing when `Content-Type` is missing, bypassing JSON validation and returning the wrong status code. Add `ShouldBindJSON` (instead of `ShouldBind`) or enforce the header in middleware for mutation endpoints. |

---

## High

| ID | Title | Finding | Notes |
|---|---|---|---|
| B-03 | Replace raw validator messages with human-readable errors | F-02 | `gin/validator` errors expose struct field paths and tag names. Map validation tag errors to user-facing messages in the handler layer. E.g., `"SeatIDs" failed on "min"` → `"seat_ids must contain at least 1 seat"`. |
| B-04 | Strip internal call-chain prefixes from error messages | F-04 | `"release redis session: invalid booking status transition"` leaks infrastructure layer. Wrap domain errors without exposing the call path. |
| B-05 | Add payment/checkout step to booking flow | — | Currently users confirm for free. A payment placeholder (even a mock) is needed before any production use. |
| B-06 | Seat selection time-limit countdown in UI | — | Hold TTL is 10 minutes but there is no visual countdown. Users lose seats without warning when the hold expires. |

---

## Medium

| ID | Title | Finding | Notes |
|---|---|---|---|
| B-07 | Fix `hold_ttl` log format | F-05 | Log as `cfg.Booking.HoldTTL.String()` (`"10m"`) instead of the raw `time.Duration` nanosecond integer (`600000000000`). One-line fix. |
| B-08 | Add hold-expiry notification in UI | — | When a held session expires (hold TTL elapses), the seat map polling will show seats freed, but there is no user-facing message explaining why the booking page changed. |
| B-09 | Admin: add showtime form should list existing movies | — | `/admin/movies/new` page requires knowing a movie ID to attach a showtime. A dropdown of existing movies would prevent 404 errors from manual ID entry. |
| B-10 | Booking history: show movie title and showtime | — | `/bookings` page shows booking IDs and seat numbers but not which movie/hall/time, making the list hard to interpret. Join on showtime data at the application layer. |
| B-11 | Add `400 INVALID_JSON` response for truly malformed body | — | Malformed JSON currently returns a generic `400` with a parse error string rather than the `{"code":"INVALID_JSON","message":"..."}` structured format. |
| B-12 | Rate limit the hold endpoint | — | No rate limiting on `POST .../hold`. A single client can make rapid hold/release cycles to block seats from other users without completing a booking. |
| B-13 | Add Grafana pre-built dashboard JSON | — | Prometheus and Grafana are provisioned, but no dashboard JSON is included. Users must build dashboards from scratch. Add at least one dashboard covering: requests/s, p50/p99 latency, in-flight requests, hold vs. confirm counts. |

---

## Low

| ID | Title | Finding | Notes |
|---|---|---|---|
| B-14 | Replace hardcoded `admin:admin` default in documentation | — | `CLAUDE.md` API table shows `Basic Auth (admin:admin)`. The actual default is now `admin:changeme` per M12. Update docs. |
| B-15 | Add `X-Request-ID` to client-visible error responses | — | `X-Request-ID` is present on responses but not included in error JSON bodies. Correlating a reported error to a server log requires guessing which request it was. |
| B-16 | Frontend seat grid: add row/seat label tooltips | — | Seat IDs like `A1`, `B12` are shown as small buttons with no label on hover. On mobile screens the ID is not visible at all. |
| B-17 | Admin: confirmation dialog before movie/showtime creation | — | No confirmation step. Submitting the form twice creates duplicate entries. |
| B-18 | Pagination on `/api/v1/movies` | — | Currently returns all movies in one response. With a large catalog this will grow unbounded. Add `?limit=` and `?offset=` query params. |
| B-19 | Structured logging: add `showtime_id` and `session_id` to booking logs | — | Server logs for hold/confirm/release only show the HTTP path. Adding domain IDs makes incident investigation faster. |
| B-20 | Add `created_at` to `GET /movies` response | — | Movie cards have no indication of when they were added. Useful for "New this week" features later. |
