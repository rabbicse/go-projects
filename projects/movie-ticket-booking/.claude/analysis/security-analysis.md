# Security Analysis

_Based on full source read — 2026-06-08_

Severity: 🔴 Critical | 🟠 High | 🟡 Medium | 🟢 Low / Informational

---

## SEC-01 🔴 No Authentication

**Description**: There is no authentication system. `user_id` is a plain string accepted in request bodies and query parameters. Any client can impersonate any user by supplying any `user_id` value.

**Impact**: A malicious user can:
- View another user's booking history (`GET /users/:userId/bookings`)
- Confirm another user's held session (if they know the `session_id`)
- Release another user's held seats (denial of service for other users)

**Note**: `session.UserID != userID` check in `ConfirmBooking` and `ReleaseBooking` does provide authorization at the session level — but since user_id is unauthenticated, this is trivially bypassed by supplying the victim's `user_id`.

**Fix**: Implement JWT or session-cookie authentication. `user_id` should be extracted from a verified token, never from the request body.

---

## SEC-02 🔴 Hardcoded Admin Credentials in Source Code

**Location**: `backend/internal/interfaces/http/router.go:57`
```go
gin.BasicAuth(gin.Accounts{"admin": "admin"})
```

**Impact**: Anyone who reads the source code (public GitHub repo) has admin access. The admin API allows creating movies and showtimes — low direct risk, but it is a privileged endpoint with no access control in practice.

**Fix**: Read from `ADMIN_USER` / `ADMIN_PASSWORD` environment variables. Add to `.env.example`. Never commit credentials.

---

## SEC-03 🟠 CORS Wildcard (`*`)

**Location**: `backend/cmd/api/main.go:56`, propagated to `CORS()` middleware
```go
AllowedOrigins: []string{"*"}
```

**Impact**: Any website can make credentialed requests to the API from a user's browser. In combination with the lack of authentication, this means a malicious website can make API calls in the context of any user's session (if auth is later added with cookies).

**Fix**: Restrict to specific frontend origins in production. Keep `*` only in local dev mode (`GIN_MODE=debug`).

---

## SEC-04 🟠 Frontend Admin Auth via `localStorage`

**Location**: `frontend/src/app/admin/`

**Impact**: Admin credentials stored in `localStorage` are accessible to any JavaScript running on the page (XSS attack). Since the backend uses HTTP Basic Auth, the credentials are also transmitted in every request header (base64-encoded, not encrypted without HTTPS).

**Fix**: Use httpOnly session cookies. Implement proper server-side session management for admin.

---

## SEC-05 🟡 No Rate Limiting

**Description**: No rate limiting on any endpoint. `POST /hold` is the most sensitive — it acquires Redis locks.

**Attack**: An attacker with a list of valid showtime IDs can:
1. Flood hold requests for all seats in a showtime, blocking legitimate purchases.
2. Repeat for all showtimes to prevent any booking (denial of service against the booking system).
3. Max hold TTL is 10 minutes, so they'd need to maintain ~72 concurrent sessions per 80-seat hall to block it continuously.

**Fix**: Add per-IP rate limiting middleware (e.g., `golang.org/x/time/rate` or `gin-contrib/ratelimit`). Consider per-userID limits for hold endpoints.

---

## SEC-06 🟡 `user_id` Accepted in DELETE Body

**Location**: `backend/internal/interfaces/http/handler/booking_handler.go:86`
```go
func (h *BookingHandler) ReleaseBooking(c *gin.Context) {
    var req dto.ConfirmRequest
    if err := c.ShouldBindJSON(&req); err != nil {
```

**Issue**: HTTP DELETE with a request body is non-standard. Many HTTP clients, proxies, and load balancers strip the body from DELETE requests. If the body is stripped, `ShouldBindJSON` will fail and the endpoint returns 400 for all release attempts.

Additionally, `user_id` in the body is unauthenticated (see SEC-01).

**Fix**: Move `user_id` to a query parameter or header for DELETE. Long-term: derive from JWT.

---

## SEC-07 🟡 Redis Address Logged at Startup

**Location**: `backend/internal/config/config.go:43-50`
```go
slog.Info("config loaded",
    "redis_addr", cfg.Redis.Addr,
    "mongodb_uri", cfg.MongoDB.URI,
    ...
)
```

**Issue**: Connection strings are logged to stdout. If `REDIS_PASSWORD` is embedded in the URI (e.g., `redis://:password@host:6379`), or if MongoDB URI contains credentials, they appear in logs. Log aggregation systems (Loki, CloudWatch) would store them in plaintext.

**Fix**: Log only host:port, never full URIs or password fields. Mask sensitive config on log.

---

## SEC-08 🟡 No Input Length Limits

**Description**: No validation on:
- Number of `seat_ids` in hold request beyond `maxSeats` (currently validated correctly)
- Length of `user_id` string — could be arbitrarily long
- Length of `session_id` in URL path params

**Impact**: A very long `user_id` stored as a Redis key value or MongoDB field could cause excessive memory usage or index bloat. Low-risk currently but a hygiene issue.

**Fix**: Add `maxlength` validation via DTO binding tags.

---

## SEC-09 🟢 No CSRF Protection

**Description**: The API uses JSON bodies (not form data) and requires `Content-Type: application/json`. Modern CSRF attacks cannot easily set custom content types from cross-origin forms. Risk is low.

**Note**: Once authentication is added (SEC-01), proper CSRF tokens or SameSite cookies should be implemented.

---

## SEC-10 🟢 No HTTP Security Headers

**Description**: No middleware sets:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security` (requires HTTPS)
- `Content-Security-Policy`

These are browser-security headers. No frontend Next.js `headers()` configuration either.

**Fix**: Add security headers middleware to Gin. Add `headers()` to `next.config.ts`.

---

## SEC-11 🟢 Session ID Exposure in Frontend

**Location**: `frontend/src/app/showtimes/[showtimeId]/page.tsx`

The session ID is displayed in the checkout panel:
```typescript
<InfoRow label="Session" value={session.sessionID.slice(0, 8) + "…"} />
```

While only a prefix is shown, the full `session_id` is in memory and in the API response. If someone with access to the browser console (`sessionStorage`) knows another user's `session_id`, they could attempt to confirm or release that session.

**Impact**: Low — requires physical access to the browser.

---

## Security Summary Table

| ID | Issue | Severity | Exploitable Without Auth? |
|---|---|---|---|
| SEC-01 | No authentication | 🔴 Critical | Yes |
| SEC-02 | Hardcoded admin password | 🔴 Critical | Yes (source is public) |
| SEC-03 | CORS wildcard | 🟠 High | Yes (with browser) |
| SEC-04 | Admin auth in localStorage | 🟠 High | Via XSS |
| SEC-05 | No rate limiting | 🟡 Medium | Yes |
| SEC-06 | DELETE body | 🟡 Medium | Yes |
| SEC-07 | Credentials in logs | 🟡 Medium | Requires log access |
| SEC-08 | No input length limits | 🟡 Medium | Yes |
| SEC-09 | No CSRF | 🟢 Low | No (JSON mitigates) |
| SEC-10 | No security headers | 🟢 Low | Via XSS |
| SEC-11 | Session ID exposure | 🟢 Low | Requires local access |
