# Security Audit

**Date**: 2026-06-10  
**Scope**: Full-stack Cinema Booking System  
**Standard**: OWASP Top 10 2021 + API Security Top 10

---

## Scorecard

| Category | Score | Status |
|---|---|---|
| Authentication | 3/10 | ⚠️ No user auth |
| Authorization | 6/10 | Partial (session ownership check only) |
| Input Validation | 5/10 | Partial (Content-Type bypass, raw validator msgs) |
| Secrets Management | 6/10 | Partial (env vars, but weak defaults in source) |
| API Security | 6/10 | Security headers present, CORS overly permissive |
| Rate Limiting | 1/10 | No rate limiting on any endpoint |
| Transport Security | 4/10 | No TLS in application layer |
| Injection Prevention | 8/10 | Parameterized queries, no string interpolation |
| Cryptography | 7/10 | No custom crypto; uses stdlib `crypto/rand` |
| Dependency Security | 6/10 | No known CVEs (unverified) |
| **Overall** | **5.2/10** | Not production-ready |

---

## Critical Findings

### SEC-01 — No User Authentication

**Severity**: Critical  
**OWASP**: A07:2021 — Identification and Authentication Failures  

Any API call to `POST .../hold`, `PUT .../confirm`, or `DELETE .../sessions/:id` requires only a `user_id` string in the request body. There is no token, cookie, or cryptographic proof that the caller is who they claim to be.

```bash
# Anyone can book as any user
curl -X POST /api/v1/showtimes/X/hold \
  -H "Content-Type: application/json" \
  -d '{"user_id":"victim-user-id","seat_ids":["A1"]}'
```

The authorization check `session.UserID != userID` in `ConfirmBooking` and `ReleaseBooking` protects against accidentally touching another user's session, but provides no protection against a deliberate attacker who knows or guesses a session ID.

**Remediation**: Issue short-lived JWTs on a login endpoint. Validate the token on every booking request. Extract `user_id` from the verified token claims rather than from the request body.

---

### SEC-02 — No Rate Limiting

**Severity**: Critical  
**OWASP**: API4:2023 — Unrestricted Resource Consumption  

No rate limiting exists on any endpoint. Specific threats:

| Endpoint | Attack Vector |
|---|---|
| `POST .../hold` | Hold-and-release loop blocks hall from real users |
| `PUT .../confirm` | Brute-force session ID guessing |
| `GET .../seats` | Polling DoS on seat map |
| `POST /admin/movies` | Spam movie/showtime creation |

**Remediation**: Add a token-bucket rate limiter middleware. For the hold endpoint: 10 holds per user per minute. For unauthenticated endpoints: limit by IP using `c.ClientIP()`.

---

## High Findings

### SEC-03 — Weak Admin Credentials in Source Control

**Severity**: High  
**OWASP**: A02:2021 — Cryptographic Failures  

`docker-compose.yml` ships with `ADMIN_PASSWORD: changeme`. This is committed to the repository. Any operator who runs `make up` without explicitly overriding this has an open admin endpoint with a known password. The API surface created (`POST /admin/movies`) allows injection of arbitrary movie data.

**Remediation**: Remove the default from `docker-compose.yml`. Require it to be provided via a `.env` file that is `.gitignore`d. Add a startup check that rejects `changeme` in production mode.

### SEC-04 — CORS Allows All Origins

**Severity**: High  
**OWASP**: A05:2021 — Security Misconfiguration  

`main.go:81` hardcodes `AllowedOrigins: []string{"*"}`. The `CORS` middleware correctly reflects the requesting `Origin` header rather than sending a wildcard, but this means every origin gets the full `Access-Control-Allow-Origin` header.

The admin endpoints (`/api/v1/admin/*`) use Basic Auth, which browsers will send on cross-origin requests because CORS allows it. A malicious page can trigger admin calls from any origin.

**Remediation**: Move `AllowedOrigins` to a config env var. In production, restrict to the frontend's actual domain.

### SEC-05 — Content-Type Not Enforced

**Severity**: Medium  
**OWASP**: A03:2021 — Injection  

When `Content-Type: application/json` is absent, `ShouldBindJSON` falls back to form parsing. An attacker can send a form-encoded body that bypasses JSON validation and reaches business logic with unvalidated data.

**Remediation**: Use `ShouldBindBodyWithJSON` (Go 1.22+) or add a middleware that rejects POST/PUT requests without `application/json` content type.

---

## Medium Findings

### SEC-06 — User Identity From Request Body (No Token Binding)

**Severity**: Medium  
**OWASP**: A01:2021 — Broken Access Control  

`user_id` in hold/confirm/release is user-supplied in the request body. Even if authentication were added, the claim would need to be validated against the auth token, not trusted from the body.

**Remediation**: Extract `user_id` from JWT claims after SEC-01 is resolved. Remove it from request DTOs.

### SEC-07 — Internal Error Details in Some Responses

**Severity**: Medium  
**OWASP**: A09:2021 — Security Logging and Monitoring Failures  

The `ReleaseBooking` path returns `"release redis session: invalid booking status transition"` — the `"release redis session:"` prefix exposes the call stack to callers. The `HTTPStatusFor` default branch correctly returns a generic 500 message, but wrapped errors that match a domain sentinel pass through the domain error's `.Error()` string as the API message.

**Remediation**: In `apierr.New()`, use curated human-readable messages instead of `err.Error()` directly. Map domain error messages in the same switch statement.

---

## Low Findings

### SEC-08 — Admin Password Logged at Startup

**Severity**: Low (was present before M12)  

`config.go` no longer logs the admin password after M12 fix. The MongoDB URI is now sanitized to host:port only. No credential leakage in current implementation. ✅

### SEC-09 — Session IDs Are UUIDs (Sufficient Entropy)

**Severity**: Informational (Good)  

Session IDs are generated via `github.com/google/uuid` which uses `crypto/rand`. 128 bits of entropy. Session ID guessing is computationally infeasible. ✅

### SEC-10 — No TLS Termination in Application Layer

**Severity**: Low for demo, High for production  

The application servers bind plaintext HTTP. In the current architecture, TLS would be handled by a load balancer or reverse proxy (Nginx, Caddy, AWS ALB). This is an acceptable architectural choice but must be documented.

**Remediation for production**: Add documentation requirement for TLS termination at the load balancer. Optionally add an HTTPS redirect handler.

---

## OWASP Top 10 Coverage

| OWASP Category | Status | Finding |
|---|---|---|
| A01 Broken Access Control | ⚠️ Partial | SEC-06: user_id from body |
| A02 Cryptographic Failures | ⚠️ Partial | SEC-03: weak default password |
| A03 Injection | ✅ Pass | Parameterized MongoDB queries; no SQL |
| A04 Insecure Design | ⚠️ Partial | SEC-01: no auth architecture |
| A05 Security Misconfiguration | ⚠️ Partial | SEC-04: CORS *, SEC-10: no TLS |
| A06 Vulnerable Components | ❓ Unknown | `go list -m all` not audited |
| A07 Auth Failures | ❌ Fail | SEC-01: no user auth |
| A08 Software Integrity | ✅ Pass | go.sum verified dependencies |
| A09 Security Logging | ⚠️ Partial | SEC-07: internal msgs in responses |
| A10 SSRF | ✅ Pass | No outbound HTTP from user input |

---

## Remediation Roadmap

| Priority | Finding | Effort | Impact |
|---|---|---|---|
| P0 | SEC-01: Add JWT authentication | 3–5 days | Unblocks all auth-related gaps |
| P0 | SEC-02: Rate limiting middleware | 0.5 day | Prevents DoS/abuse |
| P1 | SEC-03: Remove weak default password | 1 hour | Prevents credential exposure |
| P1 | SEC-04: CORS from env config | 2 hours | Prevents cross-origin admin abuse |
| P1 | SEC-05: Enforce Content-Type | 2 hours | Closes validation bypass |
| P2 | SEC-06: user_id from token | Depends on SEC-01 | Closes impersonation vector |
| P2 | SEC-07: Curated error messages | 1 day | Reduces information leakage |
| P3 | SEC-10: TLS documentation | 2 hours | Operational clarity |
