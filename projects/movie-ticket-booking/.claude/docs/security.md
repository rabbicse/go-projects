# Security Review

_Phase 13 — Threat model, findings, remediations — 2026-06-09_  
_Builds on: security-analysis.md (Phase 0), api-design.md (Phase 9), backend-refactor-plan.md (Phase 5)_

---

## 1. Threat Model

### Assets

| Asset | Sensitivity | Impact if compromised |
|---|---|---|
| Confirmed booking records | High | Revenue fraud, data breach |
| Admin credentials | Critical | Full data manipulation, service disruption |
| User booking history | Medium | Privacy violation |
| Seat availability state (Redis) | Medium | Denial-of-service on booking |
| Application source code | Low | Known (GitHub) |

### Actors

| Actor | Trust | Motivation |
|---|---|---|
| Unauthenticated user | Zero | Book seats without paying, DoS |
| Authenticated user | Low | Access/cancel other users' bookings |
| Admin (BasicAuth) | High | Data manipulation, credential compromise |
| Internal infrastructure | Full | Assumed trusted network |

### Attack Surface

```
Internet
  │
  ▼
[Next.js frontend]
  │  direct API calls
  ▼
[Gin backend :8080]
  ├─ POST /api/v1/screenings/:id/reservations  ← unauthenticated, rate-limited
  ├─ PUT  /api/v1/reservations/:id/confirm     ← ownership check required
  ├─ DELETE /api/v1/reservations/:id           ← ownership check required
  ├─ GET  /api/v1/users/:userId/bookings       ← authorization required
  └─ /api/v1/admin/**                          ← BasicAuth (SEC-01 bug)

[Redis :6379]  ← internal only, no TLS in dev
[MongoDB :27017] ← internal only, no auth in dev
```

---

## 2. Finding Catalogue

Severity scale: **Critical** → **High** → **Medium** → **Low** → **Informational**

---

### SEC-01 — Hardcoded Admin Credentials

**Severity**: Critical  
**Location**: [backend/internal/interfaces/http/router.go](backend/internal/interfaces/http/router.go)  
**OWASP**: A07 — Identification and Authentication Failures

**Current code**:
```go
adminGroup := r.Group("/api/v1/admin")
adminGroup.Use(gin.BasicAuth(gin.Accounts{
    "admin": "admin",
}))
```

Any developer with read access to the repository has admin credentials for every deployment that hasn't changed the defaults.

**Fix**:
```go
// config/config.go
type AdminConfig struct {
    Username string `env:"ADMIN_USERNAME,required"`
    Password string `env:"ADMIN_PASSWORD,required"`
}

// router.go
adminGroup.Use(gin.BasicAuth(gin.Accounts{
    cfg.Admin.Username: cfg.Admin.Password,
}))
```

Add to `.env.example`:
```bash
ADMIN_USERNAME=admin
ADMIN_PASSWORD=change-me-in-production
```

Add to CI pre-commit hook: fail if `ADMIN_PASSWORD=admin` appears in any committed file.

---

### SEC-02 — Hardcoded Infrastructure IP in Config Defaults

**Severity**: High  
**Location**: [backend/internal/config/config.go](backend/internal/config/config.go)  
**OWASP**: A05 — Security Misconfiguration

**Current code**:
```go
RedisAddr:   "192.168.0.50:6379",
MongoURI:    "mongodb://192.168.0.50:27017",
```

A developer who forgets to set env vars will silently connect to someone's home network address instead of failing loudly at startup.

**Fix**:
```go
RedisAddr:   "localhost:6379",
MongoURI:    "mongodb://localhost:27017",
```

A startup connection check should fail immediately and loudly if neither default nor env var reaches a live server. Add in `cmd/api/main.go`:
```go
if err := redisClient.Ping(ctx).Err(); err != nil {
    slog.Error("redis connection failed — check REDIS_ADDR", "error", err)
    os.Exit(1)
}
```

---

### SEC-03 — No Ownership Validation on Reservation Operations

**Severity**: High  
**Location**: [backend/internal/interfaces/http/handler/booking_handler.go](backend/internal/interfaces/http/handler/booking_handler.go)  
**OWASP**: A01 — Broken Access Control

**Current behaviour**: `DELETE /sessions/:sessionId` and `PUT /sessions/:sessionId/confirm` accept any `user_id` in the request body. User A can cancel User B's reservation by guessing or observing a `sessionId`.

`sessionId` values in the current codebase are UUIDs (`uuid.New().String()`), making them unguessable, but the ownership model is conceptually broken — user identity is not verified.

**Fix** — enforce ownership at the service layer:

```go
// application/booking/service.go
func (s *BookingService) ReleaseReservation(ctx context.Context, cmd ReleaseCommand) error {
    booking, err := s.bookingRepo.FindByReservationID(ctx, cmd.ReservationID)
    if err != nil {
        return domain.ErrReservationNotFound
    }
    if booking.UserID() != cmd.UserID {
        return domain.ErrForbidden  // SEC-03 fix — ownership check
    }
    // ... proceed with release
}
```

Handler maps `domain.ErrForbidden` → `403 Forbidden` with `FORBIDDEN` error code.

Note: Until a proper authentication system exists, `user_id` is a UUID from `localStorage` — unforged in practice but not cryptographically bound to an identity. This is acceptable for a demo. The ownership check prevents the obvious IDOR vulnerability regardless.

---

### SEC-04 — Admin Authentication Stored in Browser localStorage

**Severity**: High  
**Location**: [frontend/src/app/showtimes/[showtimeId]/page.tsx](frontend/src/app/showtimes/%5BshowtimeId%5D/page.tsx)  
**OWASP**: A02 — Cryptographic Failures, A07 — Identification and Authentication Failures

**Current behaviour**: Admin credentials are stored in `localStorage`. Any JavaScript on the page (including third-party scripts, XSS payloads) can read `localStorage` and extract the credentials.

**Fix — short term (demo acceptable)**:
The admin panel's localStorage credentials are only a client-side convenience layer. The real credential check happens at the Gin `BasicAuth` middleware — the frontend just stores them to auto-populate the HTTP `Authorization` header. The risk is XSS exfiltrating credentials.

Mitigation: Use `sessionStorage` instead of `localStorage` (clears on tab close), and add a CSP header (see SEC-14) to reduce XSS attack surface.

**Fix — production**:
Replace Basic Auth with a proper flow:
1. Admin POSTs credentials to `POST /api/v1/admin/auth`
2. Server validates, issues a short-lived JWT (15 min) + `Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict`
3. Client uses the cookie automatically — no JavaScript access, immune to XSS exfiltration
4. JWT stored in httpOnly cookie cannot be read by `localStorage`, `sessionStorage`, or JS

---

### SEC-05 — No Rate Limiting on Booking Endpoints

**Severity**: High  
**Location**: [backend/internal/interfaces/http/router.go](backend/internal/interfaces/http/router.go)  
**OWASP**: A04 — Insecure Design (availability)

**Impact**: A single client can hammer `POST /reservations` in a tight loop, exhausting Redis command budget and preventing legitimate users from booking. No rate limiting also enables seat-cycling attacks (hold → release → hold to prevent others from booking).

**Fix** — Redis sliding window rate limiter:

```go
// interfaces/http/middleware/rate_limit.go
func RateLimitMiddleware(redisClient *redis.Client) gin.HandlerFunc {
    limits := map[string]rateLimit{
        "POST:/api/v1/screenings/:screeningId/reservations": {max: 10, window: 60},
        "GET:/api/v1/screenings/:screeningId/availability":  {max: 120, window: 60},
        "default": {max: 60, window: 60},
    }

    return func(c *gin.Context) {
        key := rateLimitKey(c)
        limit := limits[c.Request.Method+":"+c.FullPath()]
        if limit.max == 0 { limit = limits["default"] }

        count, err := incrementWithExpiry(c.Request.Context(), redisClient, key, limit.window)
        if err != nil {
            c.Next() // fail open — don't block on Redis error
            return
        }

        c.Header("X-RateLimit-Limit",     strconv.Itoa(limit.max))
        c.Header("X-RateLimit-Remaining", strconv.Itoa(max(0, limit.max - int(count))))
        c.Header("X-RateLimit-Reset",     strconv.FormatInt(time.Now().Add(time.Duration(limit.window)*time.Second).Unix(), 10))

        if int(count) > limit.max {
            c.Header("Retry-After", strconv.Itoa(limit.window))
            c.AbortWithStatusJSON(http.StatusTooManyRequests, errorResponse("RATE_LIMIT_EXCEEDED",
                "Too many requests. Please retry after "+strconv.Itoa(limit.window)+" seconds."))
            return
        }
        c.Next()
    }
}

func rateLimitKey(c *gin.Context) string {
    userID, _ := c.Get("user_id")
    if uid, ok := userID.(string); ok && uid != "" {
        return fmt.Sprintf("ratelimit:%s:%s:%s", c.FullPath(), c.Request.Method, uid)
    }
    return fmt.Sprintf("ratelimit:%s:%s:%s", c.FullPath(), c.Request.Method, c.ClientIP())
}
```

---

### SEC-06 — CORS Allows All Origins

**Severity**: High (production), Low (development)  
**Location**: [backend/internal/interfaces/http/router.go](backend/internal/interfaces/http/router.go)  
**OWASP**: A05 — Security Misconfiguration

**Current code**:
```go
corsConfig.AllowAllOrigins = true
```

In production this allows any website to make credentialed cross-origin requests to the API.

**Fix** (designed in Phase 9):
```go
// config/config.go
type CORSConfig struct {
    AllowedOrigins []string `env:"CORS_ALLOWED_ORIGINS" envSeparator:"," envDefault:"http://localhost:3000"`
}

// middleware/cors.go
corsConfig := cors.Config{
    AllowOrigins:  cfg.CORS.AllowedOrigins,
    AllowMethods:  []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
    AllowHeaders:  []string{"Content-Type", "Authorization", "X-Request-ID", "Idempotency-Key"},
    ExposeHeaders: []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
    MaxAge:        12 * time.Hour,
}
```

`.env.example`:
```bash
CORS_ALLOWED_ORIGINS=http://localhost:3000
# Production: CORS_ALLOWED_ORIGINS=https://cinebook.example.com
```

---

### SEC-07 — Insufficient Input Validation

**Severity**: Medium  
**Location**: [backend/internal/interfaces/http/handler/booking_handler.go](backend/internal/interfaces/http/handler/booking_handler.go)  
**OWASP**: A03 — Injection

**Issues**:
1. `user_id` is accepted as any string — no UUID format validation
2. `seat_ids` array items have no format/length constraints
3. No trimming of whitespace from string inputs
4. No maximum string length on free-text fields (movie title, description)

**Fix** — enforce via Gin binding tags and a custom validator:

```go
// interfaces/http/dto/booking.go
type ReserveSeatsRequest struct {
    UserID  string   `json:"user_id"  binding:"required,uuid4"`
    SeatIDs []string `json:"seat_ids" binding:"required,min=1,max=4,dive,min=2,max=5,alphanum"`
}

type CreateMovieRequest struct {
    ID          string   `json:"id"          binding:"required,min=3,max=50,alphanum_hyphen"`
    Title       string   `json:"title"       binding:"required,min=1,max=200"`
    Description string   `json:"description" binding:"required,min=10,max=2000"`
    Rating      float64  `json:"rating"      binding:"required,min=0,max=10"`
    DurationMin int      `json:"duration_min" binding:"required,min=1,max=600"`
    Genres      []string `json:"genres"      binding:"required,min=1,max=10,dive,min=1,max=50"`
    PosterURL   string   `json:"poster_url"  binding:"required,url"`
}
```

Register UUID validator in `main.go`:
```go
if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
    v.RegisterValidation("uuid4", validateUUID4)
    v.RegisterValidation("alphanum_hyphen", validateAlphanumHyphen)
}
```

---

### SEC-08 — No HTTPS Enforcement

**Severity**: Medium  
**Location**: Infrastructure  
**OWASP**: A02 — Cryptographic Failures

**Context**: The Go backend serves plain HTTP on :8080. In development this is appropriate. In production, TLS must be terminated.

**Recommended production topology**:
```
Client → HTTPS (443) → [Nginx/Caddy/AWS ALB] → HTTP (8080) → Go backend
```

TLS termination at the load balancer is the standard pattern for containerised backends. The Go backend does not need to handle TLS certificates directly.

**HSTS header** (enforces HTTPS on future browser requests):
```go
// middleware/security_headers.go — add to all responses
c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
```

This header is harmless in development (browsers ignore it for `localhost`) and critical in production.

**Redirect HTTP → HTTPS** at the load balancer level (not in Go):
```nginx
# nginx example
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

---

### SEC-09 — No Request Body Size Limit

**Severity**: Medium  
**Location**: [backend/internal/interfaces/http/router.go](backend/internal/interfaces/http/router.go)  
**OWASP**: A04 — Insecure Design (availability)

A client can send a 1GB JSON body to any endpoint. The Go HTTP server will read the entire body into memory before the handler sees it.

**Fix** — wrap every request body:

```go
// middleware/body_limit.go
const maxBodyBytes = 1 << 20 // 1 MB

func BodyLimitMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
        c.Next()
    }
}
```

Register before any handler that reads the body:
```go
r.Use(middleware.BodyLimitMiddleware())
```

Gin will return a `413 Request Entity Too Large` when the limit is exceeded.

---

### SEC-10 — MongoDB BSON Injection Risk

**Severity**: Medium  
**Location**: [backend/internal/infrastructure/persistence/mongodb/](backend/internal/infrastructure/persistence/mongodb/)  
**OWASP**: A03 — Injection

**Current status**: The codebase uses `bson.D{{"field", value}}` for all queries — this treats `value` as a typed Go value, not as a raw BSON operator. A string value of `{"$ne": ""}` is passed as the literal string `{"$ne": ""}`, not as a BSON operator. **Current code is safe.**

**The risk pattern to avoid** (never do this):
```go
// UNSAFE — user input interpreted as BSON
filter := bson.M{"user_id": c.Query("user_id")}  // $ne, $regex, etc. could be injected
```

**The safe pattern** (what current code does correctly):
```go
// SAFE — explicit typed field
filter := bson.D{{"user_id", userID}}  // userID is always a string value
```

**Additional protection** — validate that user-controlled string inputs do not contain `$` prefix (MongoDB operator prefix):

```go
// lib/validate.go
func NoMongoOperators(s string) error {
    if strings.HasPrefix(strings.TrimSpace(s), "$") {
        return errors.New("invalid input: operator characters not allowed")
    }
    return nil
}
```

Apply to `user_id` and any string parameter used in MongoDB queries.

---

### SEC-11 — Sensitive Error Details in HTTP Responses

**Severity**: Medium  
**Location**: [backend/internal/interfaces/http/handler/](backend/internal/interfaces/http/handler/)  
**OWASP**: A05 — Security Misconfiguration

**Current behaviour**: Internal error messages from MongoDB (`mongo: no documents in result`) and Redis (`WRONGTYPE Operation against a key holding the wrong kind of value`) leak into HTTP responses, revealing infrastructure details to clients.

**Fix** — a central error mapper in the handler layer:

```go
// interfaces/http/handler/errors.go
func httpError(c *gin.Context, err error) {
    reqID, _ := c.Get("request_id")

    switch {
    case errors.Is(err, domain.ErrSeatsUnavailable):
        c.JSON(http.StatusConflict, errorEnvelope("SEATS_UNAVAILABLE",
            "One or more requested seats are no longer available", reqID))
    case errors.Is(err, domain.ErrReservationNotFound):
        c.JSON(http.StatusNotFound, errorEnvelope("RESERVATION_NOT_FOUND",
            "Reservation not found or has expired", reqID))
    case errors.Is(err, domain.ErrAlreadyConfirmed):
        c.JSON(http.StatusConflict, errorEnvelope("RESERVATION_ALREADY_CONFIRMED",
            "This reservation has already been confirmed", reqID))
    case errors.Is(err, domain.ErrForbidden):
        c.JSON(http.StatusForbidden, errorEnvelope("FORBIDDEN",
            "You do not have permission to perform this action", reqID))
    default:
        // Log the real error, return only request_id to the client
        slog.Error("unhandled internal error",
            "request_id", reqID,
            "error", err,
        )
        c.JSON(http.StatusInternalServerError, errorEnvelope("INTERNAL_ERROR",
            "An unexpected error occurred. Reference: "+fmt.Sprintf("%v", reqID), reqID))
    }
}
```

The `INTERNAL_ERROR` response includes `request_id` so the user can report it, but reveals nothing about the infrastructure.

---

### SEC-12 — No Ownership Validation on User Booking History

**Severity**: Medium  
**Location**: `GET /api/v1/users/:userId/bookings`  
**OWASP**: A01 — Broken Access Control

**Current behaviour**: Any client can request the booking history of any `userId` by constructing the URL. There is no session or token binding `userId` to the requesting client.

**Current mitigation**: `userId` is a UUID generated client-side and stored in `localStorage`. It is unguessable in practice (122 bits of entropy). The risk is enumeration or leakage of UUIDs from a compromised client.

**Fix — minimum**: Validate that the `userId` in the URL matches the `userId` in the request body/session. Since there is no authentication system, this is architecturally impossible to enforce currently.

**Fix — proper**: Implement JWT authentication. The JWT's `sub` claim is the user's canonical ID. The handler validates `params.userId == jwt.sub`.

**Document this as accepted risk** for the demo until authentication is added.

---

### SEC-13 — Missing Security Headers

**Severity**: Medium  
**Location**: [backend/internal/interfaces/http/router.go](backend/internal/interfaces/http/router.go), [frontend/](frontend/)  
**OWASP**: A05 — Security Misconfiguration

**Fix** — security headers middleware:

```go
// interfaces/http/middleware/security_headers.go
func SecurityHeadersMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Prevent MIME-type sniffing
        c.Header("X-Content-Type-Options", "nosniff")
        // Prevent clickjacking
        c.Header("X-Frame-Options", "DENY")
        // Force HTTPS on future requests (ignored on HTTP/localhost)
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        // Disable browser features not needed by the API
        c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        // Referrer policy
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        // Remove server identification
        c.Header("Server", "")
        c.Next()
    }
}
```

**Next.js security headers** (`next.config.ts`):

```typescript
const securityHeaders = [
  { key: "X-Content-Type-Options",       value: "nosniff" },
  { key: "X-Frame-Options",              value: "DENY" },
  { key: "Referrer-Policy",              value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy",           value: "camera=(), microphone=(), geolocation=()" },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",    // Next.js requires unsafe-inline for hydration
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",          // allow poster images from HTTPS
      "connect-src 'self' http://localhost:8080",  // API URL
      "frame-ancestors 'none'",
    ].join("; "),
  },
];

module.exports = {
  async headers() {
    return [{ source: "/(.*)", headers: securityHeaders }];
  },
};
```

---

### SEC-14 — No Dependency Vulnerability Scanning

**Severity**: Low (process)  
**Location**: CI pipeline  
**OWASP**: A06 — Vulnerable and Outdated Components

**Fix** — add to CI:

```yaml
# .github/workflows/security.yml
jobs:
  go-vuln-check:
    name: Go Vulnerability Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - run: cd backend && govulncheck ./...

  npm-audit:
    name: NPM Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: cd frontend && npm ci && npm audit --audit-level=high
```

Also add `govulncheck ./...` to the `Makefile`:
```makefile
vuln-check:
	govulncheck ./...
```

---

### SEC-15 — Docker Containers Run as Root

**Severity**: Low (defence-in-depth)  
**Location**: [backend/Dockerfile](backend/Dockerfile), [frontend/Dockerfile](frontend/Dockerfile)  
**OWASP**: A05 — Security Misconfiguration

**Fix** — use a non-root user in Dockerfiles:

```dockerfile
# backend/Dockerfile (target — using distroless)
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /server ./cmd/api

# Distroless: no shell, no package manager, minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /server /server
# nonroot tag means the image runs as uid 65532 by default
EXPOSE 8080
ENTRYPOINT ["/server"]
```

```dockerfile
# frontend/Dockerfile
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid 1001 nextjs
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
```

---

### SEC-16 — Redis and MongoDB Have No Authentication in Development Config

**Severity**: Informational  
**Location**: [docker-compose.yml](docker-compose.yml)  
**OWASP**: A05 — Security Misconfiguration

**Current state**: The development `docker-compose.yml` starts Redis and MongoDB with no password (standard for local dev). This is fine as long as ports are not exposed to the network.

**Risk**: `ports: "6379:6379"` in docker-compose.yml means Redis is accessible from the host and (if on an open network) potentially from the LAN.

**Fix for dev**:
```yaml
# docker-compose.yml — bind to localhost only
redis:
  image: redis:7-alpine
  ports:
    - "127.0.0.1:6379:6379"   # localhost only, not 0.0.0.0
```

**For production**: Redis must have `requirepass` set via `REDIS_PASSWORD` env var. MongoDB must have auth enabled. Both handled via the config module.

---

## 3. OWASP Top 10 (2021) Coverage

| Category | Status | Findings |
|---|---|---|
| A01 Broken Access Control | 🔴 Partial | SEC-03 (no ownership), SEC-12 (no auth on history) |
| A02 Cryptographic Failures | 🟡 Dev only | SEC-04 (localStorage admin), SEC-08 (no HTTPS in dev) |
| A03 Injection | 🟢 Low risk | SEC-07 (validation gaps), SEC-10 (BSON — safe but document) |
| A04 Insecure Design | 🟡 Partial | SEC-05 (no rate limiting), SEC-03 (no auth system) |
| A05 Security Misconfiguration | 🔴 Critical | SEC-01 (hardcoded creds), SEC-06 (CORS *), SEC-13 (no security headers) |
| A06 Vulnerable Components | 🟡 Process | SEC-14 (no vuln scanning in CI) |
| A07 Auth Failures | 🔴 Present | SEC-01 (hardcoded admin), SEC-03 (no user auth) |
| A08 Software Integrity | 🟢 N/A | No update mechanism, no auto-update |
| A09 Logging Failures | 🟢 Addressed | Phase 11 structured logging + PII prohibition |
| A10 SSRF | 🟢 N/A | No outbound HTTP calls from the backend |

---

## 4. Authentication Design (Future State)

The current project has no authentication system. This is acceptable for a portfolio demo. When adding auth:

### User Authentication (JWT)

```
POST /api/v1/auth/register  →  { user_id, email, password }
POST /api/v1/auth/login     →  { email, password }
                            ←  Set-Cookie: access_token=...; HttpOnly; Secure; SameSite=Strict; Max-Age=900
                               Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth/refresh

POST /api/v1/auth/refresh   →  (uses refresh_token cookie)
                            ←  new access_token cookie

POST /api/v1/auth/logout    →  clears cookies
```

**Token design**:
- Access token: JWT, 15-minute expiry, RS256 signed
- Refresh token: opaque random UUID, 7-day expiry, stored in Redis
- Both tokens in `HttpOnly` cookies — immune to XSS theft
- No tokens in `localStorage` or `sessionStorage`

**JWT claims**:
```json
{
  "sub":  "550e8400-e29b-41d4-a716-446655440000",
  "role": "user",
  "iat":  1749470461,
  "exp":  1749471361
}
```

**Middleware**:
```go
func JWTMiddleware(jwtSecret []byte) gin.HandlerFunc {
    return func(c *gin.Context) {
        token, err := c.Cookie("access_token")
        if err != nil {
            c.AbortWithStatusJSON(401, errorEnvelope("UNAUTHORIZED", "Authentication required", nil))
            return
        }
        claims, err := validateJWT(token, jwtSecret)
        if err != nil {
            c.AbortWithStatusJSON(401, errorEnvelope("TOKEN_EXPIRED", "Token expired, please refresh", nil))
            return
        }
        c.Set("user_id", claims.Subject)
        c.Next()
    }
}
```

### Admin Authentication

Replace BasicAuth with a dedicated admin JWT with `"role": "admin"` claim. Same httpOnly cookie flow as users, separate login endpoint.

---

## 5. Secret Management

### Development (current)

```bash
# backend/.env — never commit, in .gitignore
ADMIN_USERNAME=admin
ADMIN_PASSWORD=dev-password-not-for-prod
REDIS_ADDR=localhost:6379
MONGO_URI=mongodb://localhost:27017
```

### Production

**Option A — Docker Compose secrets**:
```yaml
services:
  backend:
    secrets:
      - admin_password
      - mongo_uri
    environment:
      ADMIN_PASSWORD_FILE: /run/secrets/admin_password
      MONGO_URI_FILE: /run/secrets/mongo_uri

secrets:
  admin_password:
    file: ./secrets/admin_password.txt
  mongo_uri:
    file: ./secrets/mongo_uri.txt
```

Read file-based secrets in `config.go`:
```go
func readSecret(envVar string) string {
    if val := os.Getenv(envVar); val != "" {
        return val
    }
    if path := os.Getenv(envVar + "_FILE"); path != "" {
        data, err := os.ReadFile(path)
        if err == nil {
            return strings.TrimSpace(string(data))
        }
    }
    return ""
}
```

**Option B — Kubernetes Secrets**:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cinema-booking-secrets
type: Opaque
stringData:
  ADMIN_USERNAME: admin
  ADMIN_PASSWORD: "$(openssl rand -base64 32)"
  MONGO_URI: "mongodb://user:pass@mongo-svc:27017/cinema"
```

Mount as environment variables in the Deployment spec.

**What never goes in source control**:
- Passwords or API keys of any kind
- JWT signing keys
- Database credentials
- TLS private keys

`.gitignore` must include:
```
backend/.env
frontend/.env.local
secrets/
*.pem
*.key
```

---

## 6. Remediation Roadmap

Ordered by severity × exploitability:

| Priority | Finding | Effort | Phase |
|---|---|---|---|
| P0 — Immediate | SEC-01 admin credentials hardcoded | 30min | M1 Step 1.2 |
| P0 — Immediate | SEC-02 hardcoded IP defaults | 15min | M1 Step 1.1 |
| P1 — This sprint | SEC-06 CORS wildcard | 30min | M6 Step 6.3 |
| P1 — This sprint | SEC-05 no rate limiting | 2h | M6 Step 6.5 |
| P1 — This sprint | SEC-09 no body size limit | 30min | M6 Step 6.4 |
| P1 — This sprint | SEC-13 missing security headers | 1h | M6 Step 6.6 |
| P2 — Next sprint | SEC-03 no ownership validation | 2h | M5 Step 5.3 |
| P2 — Next sprint | SEC-11 error message leakage | 2h | M7 Step 7.4 |
| P2 — Next sprint | SEC-07 input validation gaps | 2h | M7 Step 7.3 |
| P2 — Next sprint | SEC-14 no vuln scanning in CI | 1h | CI pipeline |
| P3 — Backlog | SEC-04 localStorage admin auth | 4h | Frontend rework |
| P3 — Backlog | SEC-08 HTTPS enforcement | 1h infra | Deployment config |
| P3 — Backlog | SEC-15 containers run as root | 1h | Dockerfile update |
| P4 — Future | SEC-12 booking history auth | Requires auth system | Phase 16+ |

---

## 7. Security Testing

### Static Analysis

```bash
# Go: staticcheck + gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec ./...

# Go: govulncheck (known CVEs)
govulncheck ./...

# Frontend: npm audit
npm audit --audit-level=moderate
```

### Runtime Testing

```bash
# Test rate limiting fires at 11th request
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://localhost:8080/api/v1/screenings/scr_1/reservations \
    -H "Content-Type: application/json" \
    -d '{"user_id":"550e8400-e29b-41d4-a716-446655440000","seat_ids":["A1"]}'
done
# Requests 11+ should return 429

# Test CORS rejects unknown origins
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Origin: https://evil.example.com" \
  http://localhost:8080/api/v1/movies
# Should NOT include Access-Control-Allow-Origin: https://evil.example.com in response

# Test body size limit
python3 -c "print('X' * 2000000)" | \
  curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://localhost:8080/api/v1/screenings/scr_1/reservations \
  -H "Content-Type: application/json" --data-binary @-
# Should return 413
```

Add these as shell-based integration tests in `tests/security/` that run as part of `make test-integration`.
