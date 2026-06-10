# QA Test Report

**Date**: 2026-06-10  
**Environment**: macOS, Go 1.24.2, Node 22.13.1, Backend → Redis/MongoDB on 192.168.0.50  
**Backend**: `http://localhost:8080`  
**Frontend**: `http://localhost:3000`  

---

## Summary

| Category | Total | Pass | Fail | Findings |
|---|---|---|---|---|
| Movie Browsing | 3 | 3 | 0 | — |
| Showtime | 2 | 2 | 0 | F-01 (past dates) |
| Seat Map | 2 | 2 | 0 | — |
| Booking Flow | 7 | 7 | 0 | F-04 (message leakage) |
| Validation | 5 | 3 | 2 | F-02, F-03 |
| Admin | 3 | 3 | 0 | — |
| Frontend Pages | 7 | 7 | 0 | — |
| Infrastructure | 3 | 3 | 0 | — |
| **Total** | **32** | **30** | **2** | **5 findings** |

---

## Test Cases

### Movie Browsing

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| TC-001 | `GET /api/v1/movies` — list all movies | 200, array of 5 movies with showtimes | 200, 5 movies (Dune, Oppenheimer, Inception, The Batman, Interstellar) | ✅ PASS |
| TC-002 | `GET /api/v1/movies/dune-part-two` — single movie | 200, movie with title, rating, genre, showtimes | 200, correct fields | ✅ PASS |
| TC-003 | `GET /api/v1/movies/does-not-exist` — not found | 404, structured error | 404, `{"code":"MOVIE_NOT_FOUND","message":"..."}` | ✅ PASS |

### Showtime

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| TC-004 | `GET /api/v1/showtimes/dune2-hall1-1` — valid showtime | 200, hall, start/end times, rows, seats, price | 200, correct. **Start: 2026-05-20 (past)** | ✅ PASS ⚠️ F-01 |
| TC-005 | `GET /api/v1/showtimes/bad-id` — not found | 404, structured error | 404, `{"code":"SHOWTIME_NOT_FOUND","message":"..."}` | ✅ PASS |

### Seat Map

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| TC-006 | Seat map for clean showtime | Empty array (no active holds) | `[]` (null, renders as 0 seats) | ✅ PASS |
| TC-008 | Seat map after hold | Held seats visible | 2 seats shown as `held`, `held_by_me=false` (different user_id) | ✅ PASS |

### Booking Flow

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| TC-007 | `POST .../hold` — hold 2 seats | 201, session with id, seat_ids, expires_at | 201, correct response | ✅ PASS |
| TC-012 | Confirm with wrong user_id | 403, `UNAUTHORIZED` | 403, `{"code":"UNAUTHORIZED","message":"session does not belong to this user"}` | ✅ PASS |
| TC-013 | Confirm with correct user | 200, booking with seats, total_cents, confirmed_at | 200, `{"status":"confirmed","total_cents":3000,...}` | ✅ PASS |
| TC-014 | Confirm already-confirmed session | 409, `INVALID_STATUS_TRANSITION` | 409, correct | ✅ PASS |
| TC-015 | Release held session | 204 No Content | 204 | ✅ PASS |
| TC-018 | Release confirmed session | 409, `INVALID_STATUS_TRANSITION` | 409 but message contains `"release redis session:"` prefix (F-04) | ✅ PASS ⚠️ F-04 |
| TC-019 | Release non-existent session | 404, `SESSION_NOT_FOUND` | 404, correct | ✅ PASS |

### Booking History

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| TC-016 | `GET /users/verify-user-001/bookings` | Array with 1 confirmed booking | 1 booking, correct seats and total | ✅ PASS |
| TC-017 | `GET /users/nobody-ever/bookings` | Empty array `[]` | `[]` | ✅ PASS |

### Validation

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| TC-009 | Hold already-held seat | 409, `SEATS_UNAVAILABLE` | 409, `{"code":"SEATS_UNAVAILABLE","message":"one or more seats are already held or confirmed"}` | ✅ PASS |
| TC-010 | Hold 5 seats (max=4) | 400, `MAX_SEATS_EXCEEDED` | 400, correct | ✅ PASS |
| TC-011 | Hold with empty seat array | 400 | 400, but message exposes struct path `HoldSeatsRequest.SeatIDs` (F-02) | ⚠️ FAIL |
| TC-020a | Missing `Content-Type` header | 400 `INVALID_REQUEST` | 409 `SEATS_UNAVAILABLE` — body parsed as form, validation bypassed (F-03) | ⚠️ FAIL |
| TC-020b | Malformed JSON | 400 | 400, correct | ✅ PASS |
| TC-020c | Missing `user_id` | 400 | 400, but exposes struct field name `HoldSeatsRequest.UserID` (F-02) | ⚠️ FAIL (same root cause as TC-011) |

### Admin API

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| TC-021 | No auth header | 401 | 401, empty body | ✅ PASS |
| TC-022 | Wrong password | 401 | 401 | ✅ PASS |
| TC-023 | Correct credentials | 200, movie list | 200, full list | ✅ PASS |

### Frontend Pages

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| TC-026 | Home page `/` | 200 | 200 | ✅ PASS |
| TC-027 | Movie detail `/movies/dune-part-two` | 200 | 200 | ✅ PASS |
| TC-028 | Showtime `/showtimes/dune2-hall1-1` | 200 | 200 | ✅ PASS |
| TC-029 | Bookings `/bookings` | 200 | 200 | ✅ PASS |
| TC-030 | Non-existent movie | 404 | 404 | ✅ PASS |
| TC-031 | Admin login | 200 | 200 | ✅ PASS |
| TC-032 | API proxy `/api/v1/movies` | 200 | 200 | ✅ PASS |

### Infrastructure & Observability

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| TC-024 | `GET /metrics` — Prometheus | 200, metric families present | 200, `http_requests_total`, `http_request_duration_seconds`, `http_requests_in_flight` all present | ✅ PASS |
| TC-034 | Security headers | X-Frame-Options, X-Content-Type-Options, Referrer-Policy, X-Request-ID | All present | ✅ PASS |
| TC-035 | CORS preflight | 204, correct allow headers | 204, `Access-Control-Allow-Origin` reflects request origin | ✅ PASS |

---

## Concurrency Verification

| ID | Scenario | Expected | Actual | Status |
|---|---|---|---|---|
| TC-025 | Same seat held by 5 sequential users | First succeeds, rest get 409 | User 1: 201, Users 2–5: 409 | ✅ PASS |

---

## Performance Measurements

All measurements are round-trip from localhost → localhost backend → 192.168.0.50 databases.

| Endpoint | Avg Latency | Assessment |
|---|---|---|
| `GET /api/v1/movies` (5 movies, 11 showtimes) | 11.3ms | Good |
| `GET /api/v1/movies/:id` | 11.6ms | Good |
| `GET /api/v1/showtimes/:id` | 19.8ms | Good |
| `GET /api/v1/showtimes/:id/seats` | 9.5ms | Good |
| `POST .../hold` (Redis NX + MongoDB write) | 20.8ms | Good |
| `PUT .../confirm` (Redis PERSIST + MongoDB update) | 34.0ms | Acceptable |
| Frontend `/` (server-side rendered) | 86ms | Good (first request) |
| Frontend `/movies/:id` | 75ms | Good |
| Frontend `/showtimes/:id` | 56ms | Good |

Note: Measurements include ~8ms network RTT to remote databases at 192.168.0.50.

---

## Findings

### F-01 — Seeded Showtimes Are In The Past

**Severity**: High (UX)  
**Where**: Seeder (`backend/internal/infrastructure/seeder/`)  
**Description**: All 5 demo movies have showtimes hardcoded to `2026-05-20`. Today is `2026-06-10`. Users see shows with past dates on the booking page.  
**Reproduction**: Start the app fresh, visit any showtime page.  
**Expected**: Showtimes should use relative future dates (e.g., `time.Now().Add(24 * time.Hour)`).  

### F-02 — Raw Validator Messages Exposed to Users

**Severity**: Medium (UX / API quality)  
**Where**: `POST /api/v1/showtimes/:id/hold`  
**Description**: When `seat_ids` is empty or `user_id` is missing, the error message exposes internal struct field paths: `"Key: 'HoldSeatsRequest.SeatIDs' Error:Field validation for 'SeatIDs' failed on the 'min' tag"`.  
**Expected**: `"seat_ids must contain at least 1 seat"` / `"user_id is required"`.  

### F-03 — Missing Content-Type Bypasses Validation

**Severity**: Medium (API contract)  
**Where**: `POST /api/v1/showtimes/:id/hold`  
**Description**: When `Content-Type: application/json` is absent, Gin falls back to form parsing. The request body is silently parsed as an empty form, skipping JSON validation and proceeding to the business logic layer. Result: 409 Conflict instead of 400 Bad Request.  
**Reproduction**: `curl -X POST .../hold -d '{"user_id":"x","seat_ids":["A1"]}'` (no Content-Type).  

### F-04 — Internal Call Chain Leaks in Error Messages

**Severity**: Low (API quality)  
**Where**: `DELETE /api/v1/sessions/:sessionId`  
**Description**: Releasing a confirmed session returns `"release redis session: invalid booking status transition"`. The prefix `"release redis session:"` is an internal implementation detail.  
**Expected**: `"booking cannot be released after confirmation"`.  

### F-05 — hold_ttl Logs in Nanoseconds

**Severity**: Low (operational)  
**Where**: `backend/internal/config/config.go` startup log  
**Description**: `hold_ttl` is logged as `600000000000` (nanoseconds) instead of `"10m"`. This is because `time.Duration` is passed as an `any` to `slog.Info` and formatted as an integer.  
**Fix**: `"hold_ttl", cfg.Booking.HoldTTL.String()`.  

---

## Edge Cases Tested

| Edge Case | Result |
|---|---|
| Booking history for user with no bookings | Returns `[]` (correct) |
| Confirming with wrong `user_id` | 403 Forbidden (correct) |
| Re-confirming an already-confirmed session | 409 Conflict (correct) |
| Attempting to hold more than `MAX_SEATS` | 400 Bad Request (correct) |
| Seat map for showtime with no active holds | Returns `[]` (not `null`) |
| Admin endpoints without auth | 401 (correct) |
| Non-existent movie / showtime / session | 404 with structured error (correct) |
