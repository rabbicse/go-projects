# API Design

_Phase 9 — API design review and forward specification — 2026-06-09_  
_Builds on: domain-model.md (Phase 2), backend-refactor-plan.md (Phase 5)_

---

## 1. Design Principles

This API follows REST constraints with pragmatic extensions:

1. **Resource-oriented URLs** — nouns, not verbs. `/reservations` not `/holdSeats`.
2. **HTTP semantics** — GET is safe + idempotent; PUT is idempotent; DELETE is idempotent.
3. **Ubiquitous language** — URL tokens match the domain model (Phase 2). No `showtime`, `session`, `hold` leaking through.
4. **Consistent error envelope** — every 4xx/5xx returns the same JSON shape.
5. **No breaking changes without a version bump** — additive changes (new optional fields, new endpoints) are allowed in v1. Removals and renames require `/api/v2/`.
6. **Idempotency on mutations** — `POST /reservations` and `PUT /confirm` are idempotent via the `Idempotency-Key` header.
7. **Explicit pagination** — no unbounded list responses.

---

## 2. URL Naming Convention

### Current vs Target

| Current | Target | Reason |
|---|---|---|
| `/api/v1/showtimes/:id` | `/api/v1/screenings/:id` | Domain rename: Showtime→Screening |
| `/api/v1/showtimes/:id/seats` | `/api/v1/screenings/:id/availability` | Resource name — "availability" is what the client actually reads |
| `/api/v1/showtimes/:id/hold` | `/api/v1/screenings/:id/reservations` | POST creates a SeatReservation resource |
| `/api/v1/sessions/:id/confirm` | `/api/v1/reservations/:id/confirm` | Domain rename: Session→SeatReservation |
| `/api/v1/sessions/:id` (DELETE) | `/api/v1/reservations/:id` | Same |
| `/api/v1/admin/movies/:id/showtimes` | `/api/v1/admin/movies/:id/screenings` | Consistent rename |

### Rules

```
/api/{version}/{resource}            — collection
/api/{version}/{resource}/{id}       — individual
/api/{version}/{resource}/{id}/{sub} — sub-resource or action
```

**Sub-resource vs action**: Use a sub-resource when it has its own lifecycle (`/reservations`). Use a path action when there's no separate resource to return (`/confirm`, `/release`).

```
POST /api/v1/screenings/:id/reservations  ← creates a resource (reservation)
PUT  /api/v1/reservations/:id/confirm     ← transitions state (no new resource)
DELETE /api/v1/reservations/:id           ← destroys the resource
```

---

## 3. Complete Endpoint Catalog (v1 Target)

### 3.1 Health

```
GET /health
```

Response `200 OK`:
```json
{
  "status": "ok",
  "version": "1.0.0",
  "timestamp": "2026-06-09T12:00:00Z"
}
```

No `/api/v1/` prefix — health must be reachable without API version routing (load balancer probes).

---

### 3.2 Catalog — Movies

#### `GET /api/v1/movies`

List all movies. Supports pagination and filtering.

Query parameters:

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `page` | int | 1 | 1-based |
| `page_size` | int | 20 | Max 100 |
| `genre` | string | — | Filter by genre tag |
| `sort` | string | `title` | `title`, `rating`, `created_at` |
| `order` | string | `asc` | `asc`, `desc` |

Response `200 OK`:
```json
{
  "data": [
    {
      "id": "the-matrix",
      "title": "The Matrix",
      "genres": ["Action", "Sci-Fi"],
      "rating": 8.7,
      "duration_min": 136,
      "poster_url": "https://...",
      "description": "A computer hacker...",
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 5,
    "total_pages": 1
  }
}
```

#### `GET /api/v1/movies/:movieId`

Get single movie with its upcoming screenings.

Response `200 OK`:
```json
{
  "data": {
    "id": "the-matrix",
    "title": "The Matrix",
    "genres": ["Action", "Sci-Fi"],
    "rating": 8.7,
    "duration_min": 136,
    "poster_url": "https://...",
    "description": "A computer hacker...",
    "screenings": [
      {
        "id": "matrix-screen1-2026-06-10-18-00",
        "screen": "Screen 1",
        "start_time": "2026-06-10T18:00:00Z",
        "end_time": "2026-06-10T20:16:00Z",
        "price": { "amount": 1200, "currency": "USD" },
        "available_seats": 87,
        "total_seats": 120
      }
    ],
    "created_at": "2026-01-01T00:00:00Z"
  }
}
```

`screenings` array contains only future screenings with `start_time >= now`.

---

### 3.3 Catalog — Screenings

#### `GET /api/v1/screenings/:screeningId`

Get full screening detail.

Response `200 OK`:
```json
{
  "data": {
    "id": "matrix-screen1-2026-06-10-18-00",
    "movie_id": "the-matrix",
    "movie_title": "The Matrix",
    "screen": "Screen 1",
    "start_time": "2026-06-10T18:00:00Z",
    "end_time": "2026-06-10T20:16:00Z",
    "price": { "amount": 1200, "currency": "USD" },
    "rows": 10,
    "seats_per_row": 12,
    "available_seats": 87,
    "total_seats": 120
  }
}
```

#### `GET /api/v1/screenings/:screeningId/availability`

Real-time seat map. Polled at 2s by the frontend.

Query parameters:

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `user_id` | UUID | No | If provided, seats held by this user are shown as `mine` |

Response `200 OK`:
```json
{
  "data": {
    "screening_id": "matrix-screen1-2026-06-10-18-00",
    "snapshot_at": "2026-06-09T12:00:00.123Z",
    "seats": [
      { "id": "A1", "row": "A", "number": 1, "status": "available" },
      { "id": "A2", "row": "A", "number": 2, "status": "held" },
      { "id": "A3", "row": "A", "number": 3, "status": "mine" },
      { "id": "A4", "row": "A", "number": 4, "status": "confirmed" }
    ]
  }
}
```

Seat status values:

| Value | Meaning |
|---|---|
| `available` | Free to select |
| `held` | Another user has a temporary hold |
| `mine` | The requesting user holds this seat |
| `confirmed` | Permanently booked (no TTL) |
| `unavailable` | Disabled / maintenance |

`snapshot_at` lets clients detect stale responses from cache layers.

**Caching note**: This endpoint must include `Cache-Control: no-store` — it is real-time and must never be CDN-cached.

---

### 3.4 Reservations

#### `POST /api/v1/screenings/:screeningId/reservations`

Hold 1–N seats atomically. N is controlled by `MAX_SEATS_PER_SESSION` (default 4).

Headers:

| Header | Required | Notes |
|---|---|---|
| `Idempotency-Key` | Recommended | UUID. Re-sending same key within 60s returns cached response |
| `Content-Type` | Yes | `application/json` |

Request body:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "seat_ids": ["A3", "A4"]
}
```

Response `201 Created`:
```json
{
  "data": {
    "reservation_id": "res_7f3e2a1b",
    "screening_id": "matrix-screen1-2026-06-10-18-00",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "seat_ids": ["A3", "A4"],
    "status": "held",
    "price_per_seat": { "amount": 1200, "currency": "USD" },
    "total": { "amount": 2400, "currency": "USD" },
    "held_at": "2026-06-09T12:00:00Z",
    "expires_at": "2026-06-09T12:10:00Z"
  }
}
```

Response `409 Conflict` — one or more seats already taken:
```json
{
  "error": {
    "code": "SEATS_UNAVAILABLE",
    "message": "One or more requested seats are no longer available",
    "details": { "unavailable_seat_ids": ["A3"] }
  }
}
```

Response `422 Unprocessable Entity` — validation failure:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": {
      "fields": [
        { "field": "seat_ids", "message": "Must select between 1 and 4 seats" }
      ]
    }
  }
}
```

#### `PUT /api/v1/reservations/:reservationId/confirm`

Convert a held reservation to a confirmed booking. Only valid within the `expires_at` window.

Headers:

| Header | Required | Notes |
|---|---|---|
| `Idempotency-Key` | Recommended | Protects against double-confirm |

Request body:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "payment_method": "card",
  "payment_token": "tok_test_4242"
}
```

`payment_method` and `payment_token` are forward-compatible fields — currently stored but not validated (payment gateway integration is Phase 16+).

Response `200 OK`:
```json
{
  "data": {
    "booking_id": "bkg_9a1c4e2d",
    "reservation_id": "res_7f3e2a1b",
    "screening_id": "matrix-screen1-2026-06-10-18-00",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "seat_ids": ["A3", "A4"],
    "status": "confirmed",
    "total": { "amount": 2400, "currency": "USD" },
    "confirmed_at": "2026-06-09T12:03:14Z"
  }
}
```

Response `404 Not Found` — reservation expired or doesn't exist:
```json
{
  "error": {
    "code": "RESERVATION_NOT_FOUND",
    "message": "Reservation not found or has expired",
    "details": { "reservation_id": "res_7f3e2a1b" }
  }
}
```

Response `409 Conflict` — reservation already confirmed:
```json
{
  "error": {
    "code": "RESERVATION_ALREADY_CONFIRMED",
    "message": "This reservation has already been confirmed"
  }
}
```

#### `DELETE /api/v1/reservations/:reservationId`

Release a held reservation. Idempotent — deleting an already-released or expired reservation returns `204`.

Request body:
```json
{ "user_id": "550e8400-e29b-41d4-a716-446655440000" }
```

Response `204 No Content` — released (or already gone).

Response `403 Forbidden` — user_id doesn't own this reservation:
```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "You do not own this reservation"
  }
}
```

---

### 3.5 User Bookings

#### `GET /api/v1/users/:userId/bookings`

Booking history for a user. Cursor-based pagination (booking IDs are sorted by `confirmed_at`).

Query parameters:

| Parameter | Type | Default | Notes |
|---|---|---|---|
| `cursor` | string | — | Opaque cursor from previous response |
| `page_size` | int | 20 | Max 50 |
| `status` | string | — | `confirmed`, `cancelled` |

Response `200 OK`:
```json
{
  "data": [
    {
      "booking_id": "bkg_9a1c4e2d",
      "movie_title": "The Matrix",
      "screening_start": "2026-06-10T18:00:00Z",
      "screen": "Screen 1",
      "seat_ids": ["A3", "A4"],
      "status": "confirmed",
      "total": { "amount": 2400, "currency": "USD" },
      "confirmed_at": "2026-06-09T12:03:14Z"
    }
  ],
  "pagination": {
    "cursor": "bkg_9a1c4e2d",
    "next_cursor": null,
    "has_more": false,
    "page_size": 20
  }
}
```

**Why cursor pagination here**: Bookings are append-only and sorted by time. Cursor pagination avoids the offset drift problem (a new booking inserted between two pages shifts all offsets). For the movies and admin lists, offset pagination is acceptable because writes are rare.

---

### 3.6 Admin (Protected)

All `/api/v1/admin/**` endpoints require HTTP Basic Auth (`Authorization: Basic <base64(user:pass)>`). The credentials come from env vars (`ADMIN_USERNAME`, `ADMIN_PASSWORD`), not source code.

**Production note**: Replace Basic Auth with an API key (`Authorization: Bearer <api_key>`) or OAuth2 client credentials for any real deployment. Basic Auth over TLS is acceptable for a demo.

#### `GET /api/v1/admin/movies`

Same as `GET /api/v1/movies` but includes all movies regardless of screening status.

#### `POST /api/v1/admin/movies`

Create a new movie.

Request body:
```json
{
  "id": "inception",
  "title": "Inception",
  "genres": ["Action", "Sci-Fi", "Thriller"],
  "rating": 8.8,
  "duration_min": 148,
  "poster_url": "https://...",
  "description": "A thief who steals corporate secrets..."
}
```

Response `201 Created`: full movie object (same shape as `GET /api/v1/movies/:id`).

Response `409 Conflict`:
```json
{
  "error": {
    "code": "MOVIE_ALREADY_EXISTS",
    "message": "A movie with ID 'inception' already exists"
  }
}
```

#### `POST /api/v1/admin/movies/:movieId/screenings`

Add a screening to a movie. Validates no overlap with existing screenings for the same screen.

Request body:
```json
{
  "id": "inception-screen2-2026-06-11-20-00",
  "screen": "Screen 2",
  "start_time": "2026-06-11T20:00:00Z",
  "end_time": "2026-06-11T22:28:00Z",
  "rows": 10,
  "seats_per_row": 12,
  "price": { "amount": 1400, "currency": "USD" }
}
```

Response `201 Created`: full screening object.

Response `409 Conflict` — hall overlap:
```json
{
  "error": {
    "code": "SCREENING_OVERLAP",
    "message": "Screen 2 is already booked during this time window",
    "details": {
      "conflicting_screening_id": "other-movie-screen2-2026-06-11-19-00"
    }
  }
}
```

---

## 4. Error Format

Every error response uses the same envelope regardless of status code:

```json
{
  "error": {
    "code": "MACHINE_READABLE_CODE",
    "message": "Human-readable explanation",
    "details": {},          ← optional, error-specific context
    "request_id": "req_abc123",
    "timestamp": "2026-06-09T12:00:00Z"
  }
}
```

### Error Code Catalogue

| HTTP Status | Code | Trigger |
|---|---|---|
| 400 | `BAD_REQUEST` | Malformed JSON |
| 422 | `VALIDATION_ERROR` | Field validation failure |
| 401 | `UNAUTHORIZED` | Missing/invalid auth |
| 403 | `FORBIDDEN` | Valid auth, wrong owner |
| 404 | `MOVIE_NOT_FOUND` | Movie ID not found |
| 404 | `SCREENING_NOT_FOUND` | Screening ID not found |
| 404 | `RESERVATION_NOT_FOUND` | Expired or never existed |
| 404 | `BOOKING_NOT_FOUND` | Booking ID not found |
| 409 | `SEATS_UNAVAILABLE` | Atomic lock failed |
| 409 | `RESERVATION_ALREADY_CONFIRMED` | Double-confirm attempt |
| 409 | `MOVIE_ALREADY_EXISTS` | Duplicate movie ID |
| 409 | `SCREENING_OVERLAP` | Hall time conflict |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Unexpected server error |
| 503 | `SERVICE_UNAVAILABLE` | Redis/MongoDB down |

**Principle**: 500 errors never expose stack traces. Log the full error server-side, return only `INTERNAL_ERROR` with the `request_id` so the caller can report it.

---

## 5. Response Envelope

All successful responses wrap data in a `data` key. This reserves the top-level namespace for future envelope fields (`meta`, `links`, `warnings`) without breaking existing clients.

```json
{ "data": { ... } }              ← single resource
{ "data": [ ... ], "pagination": { ... } }  ← collection
```

`204 No Content` is the only success response with no body.

---

## 6. Pagination

### Offset Pagination (Movies, Admin Lists)

```
GET /api/v1/movies?page=2&page_size=20
```

Response includes:
```json
"pagination": {
  "page": 2,
  "page_size": 20,
  "total": 47,
  "total_pages": 3
}
```

Use where: data changes infrequently, `COUNT(*)` is cheap, UI needs page numbers.

### Cursor Pagination (Booking History)

```
GET /api/v1/users/:userId/bookings?cursor=bkg_9a1c4e2d&page_size=20
```

The cursor is the last `booking_id` from the previous page. The query translates to `WHERE id > cursor ORDER BY id LIMIT page_size + 1` (fetch +1 to detect `has_more`).

Response includes:
```json
"pagination": {
  "cursor": "bkg_9a1c4e2d",
  "next_cursor": "bkg_4f2b1a9c",
  "has_more": true,
  "page_size": 20
}
```

Use where: append-only collections, no page-number UI needed, large datasets.

---

## 7. Rate Limiting

Headers returned on every response:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1749470461
Retry-After: 14         ← only on 429
```

Limits by endpoint class:

| Endpoint Class | Limit | Window | Key |
|---|---|---|---|
| `POST /reservations` | 10 | 60s | `user_id` |
| `GET /availability` | 120 | 60s | IP |
| `GET /movies`, `GET /screenings` | 60 | 60s | IP |
| `POST /admin/*` | 30 | 60s | Admin account |
| Everything else | 60 | 60s | IP |

The `POST /reservations` limit is the most important — a malicious or buggy client retrying 10 holds/sec would thrash Redis unnecessarily.

Implementation: Redis INCR + EX (sliding window) or token bucket. The current repo has `make load-test-concurrent` — run it to verify rate limit headers appear under load.

---

## 8. HTTP Headers

### Request Headers

| Header | Required | Notes |
|---|---|---|
| `Content-Type: application/json` | Yes (mutations) | |
| `Accept: application/json` | Recommended | |
| `X-Request-ID` | Optional | Client-provided correlation ID; echoed in response |
| `Idempotency-Key` | Recommended (mutations) | UUID; cached for 60s |

### Response Headers

| Header | Always | Notes |
|---|---|---|
| `Content-Type: application/json` | Yes | |
| `X-Request-ID` | Yes | Server-generated if client didn't provide one |
| `Cache-Control` | Yes | Varies by endpoint (see §9) |

---

## 9. Caching Strategy

| Endpoint | Cache-Control | Rationale |
|---|---|---|
| `GET /api/v1/movies` | `public, max-age=60` | CDN-cacheable; changes rarely |
| `GET /api/v1/movies/:id` | `public, max-age=30` | Includes upcoming screenings |
| `GET /api/v1/screenings/:id` | `public, max-age=30` | Static screening metadata |
| `GET /api/v1/screenings/:id/availability` | `no-store` | Real-time; never cache |
| `GET /api/v1/users/:userId/bookings` | `private, no-store` | User-specific |
| All mutations | `no-store` | |
| `GET /health` | `no-cache` | |

---

## 10. CORS

Current: `AllowAllOrigins: true` in dev (SM-10 in architecture-smells.md). Production config:

```go
// interfaces/http/middleware/cors.go
corsConfig := cors.Config{
  AllowOrigins:     strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ","),
  AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
  AllowHeaders:     []string{"Content-Type", "Authorization", "X-Request-ID", "Idempotency-Key"},
  ExposeHeaders:    []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
  AllowCredentials: false,   // no cookies on this API
  MaxAge:           12 * time.Hour,
}
```

Environment variable `CORS_ALLOWED_ORIGINS` defaults to `http://localhost:3000` in `.env.example`, `https://cinebook.example.com` in production.

---

## 11. Idempotency

For `POST /reservations` and `PUT /reservations/:id/confirm`, clients SHOULD send an `Idempotency-Key` header (UUIDv4). The server:

1. On first request: execute, store `(key → response body + status)` in Redis with 60s TTL.
2. On duplicate request (same key within 60s): return stored response immediately, skip execution.

```
Idempotency-Key: 7f3e2a1b-4c8d-4e9f-a1b2-c3d4e5f60000
```

Response when key is replayed:
```
X-Idempotent-Replayed: true
```

This protects against the network retry double-booking problem. The current implementation does not have this; it's a Phase 5 / M1 addition per the backend refactor plan.

---

## 12. Versioning Strategy

Current: `/api/v1/` prefix. Strategy going forward:

| Change Type | Handling |
|---|---|
| New optional request field | Backward compatible — no version bump |
| New response field | Backward compatible — clients must ignore unknown fields |
| New endpoint | Backward compatible — no version bump |
| Field rename | **Breaking** — bump to `/api/v2/` |
| Field removal | **Breaking** — bump to `/api/v2/` |
| Endpoint removal | **Breaking** — deprecate first (6-month notice), then bump |
| Status code change | **Breaking** |

When v2 is introduced, v1 runs in parallel for a deprecation window. A `Deprecation` header is added to v1 responses:

```
Deprecation: Sat, 01 Jan 2028 00:00:00 GMT
Sunset: Mon, 01 Jul 2028 00:00:00 GMT
Link: </api/v2/movies>; rel="successor-version"
```

---

## 13. OpenAPI Specification

The current `swagger.json` lives at `backend/internal/docs/swagger.json` and is served at `/api/v1/docs/swagger.json`. The `make sync-swagger` command copies it to `docs/`.

### Forward Spec for v1 Target

The spec should be updated to reflect the renamed resources. Key `paths` changes:

```yaml
# New paths (replace old showtime/session paths)
/api/v1/screenings/{screeningId}:
  get:
    summary: Get screening details
    tags: [Catalog]
    parameters:
      - name: screeningId
        in: path
        required: true
        schema:
          type: string
    responses:
      "200":
        description: Screening details
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/ScreeningResponse"
      "404":
        $ref: "#/components/responses/NotFound"

/api/v1/screenings/{screeningId}/availability:
  get:
    summary: Get real-time seat availability
    tags: [Booking]
    parameters:
      - name: screeningId
        in: path
        required: true
        schema:
          type: string
      - name: user_id
        in: query
        required: false
        schema:
          type: string
          format: uuid
    responses:
      "200":
        description: Seat availability snapshot
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/AvailabilityResponse"

/api/v1/screenings/{screeningId}/reservations:
  post:
    summary: Reserve seats (hold)
    tags: [Booking]
    requestBody:
      required: true
      content:
        application/json:
          schema:
            $ref: "#/components/schemas/CreateReservationRequest"
    responses:
      "201":
        description: Reservation created
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/ReservationResponse"
      "409":
        $ref: "#/components/responses/Conflict"
      "422":
        $ref: "#/components/responses/ValidationError"

/api/v1/reservations/{reservationId}/confirm:
  put:
    summary: Confirm a held reservation
    tags: [Booking]
    responses:
      "200":
        description: Booking confirmed
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/BookingResponse"
      "404":
        $ref: "#/components/responses/NotFound"
      "409":
        $ref: "#/components/responses/Conflict"

/api/v1/reservations/{reservationId}:
  delete:
    summary: Release a held reservation
    tags: [Booking]
    responses:
      "204":
        description: Released
      "403":
        $ref: "#/components/responses/Forbidden"
```

### Reusable Response Schemas

```yaml
components:
  schemas:
    Money:
      type: object
      required: [amount, currency]
      properties:
        amount:   { type: integer, description: "Amount in smallest currency unit (cents)" }
        currency: { type: string, minLength: 3, maxLength: 3, example: "USD" }

    SeatStatus:
      type: string
      enum: [available, held, mine, confirmed, unavailable]

    SeatAvailability:
      type: object
      required: [id, row, number, status]
      properties:
        id:     { type: string, example: "A1" }
        row:    { type: string, example: "A" }
        number: { type: integer, example: 1 }
        status: { $ref: "#/components/schemas/SeatStatus" }

    ErrorResponse:
      type: object
      required: [error]
      properties:
        error:
          type: object
          required: [code, message]
          properties:
            code:       { type: string }
            message:    { type: string }
            details:    { type: object }
            request_id: { type: string }
            timestamp:  { type: string, format: date-time }

  responses:
    NotFound:
      description: Resource not found
      content:
        application/json:
          schema: { $ref: "#/components/schemas/ErrorResponse" }
    Conflict:
      description: State conflict
      content:
        application/json:
          schema: { $ref: "#/components/schemas/ErrorResponse" }
    ValidationError:
      description: Request validation failure
      content:
        application/json:
          schema: { $ref: "#/components/schemas/ErrorResponse" }
    Forbidden:
      description: Forbidden
      content:
        application/json:
          schema: { $ref: "#/components/schemas/ErrorResponse" }
```

---

## 14. Real-Time Alternative: SSE

The current 2-second polling on `/availability` generates 30 requests/min per connected user. At 270 concurrent viewers (the scale ceiling from `scalability-analysis.md`), that's ~8,100 requests/min against Redis.

**Option A (current): Short-poll** — simple, stateless, works behind any proxy. Keep for now.

**Option B (Phase 11+): SSE** — Server-Sent Events.

```
GET /api/v1/screenings/:screeningId/availability/stream
Accept: text/event-stream
```

Response stream:
```
event: availability
data: {"seats": [...], "snapshot_at": "2026-06-09T12:00:00.123Z"}

event: availability
data: {"seats": [...], "snapshot_at": "2026-06-09T12:00:02.456Z"}
```

The backend broadcasts a seat-state update whenever a Redis key changes (via Keyspace Notifications or an in-process event from the reservation service). SSE reduces backend load by ~95% under high concurrency because updates are pushed only on change, not pulled every 2s.

**Migration path**: Add the SSE endpoint in M6. The frontend falls back to polling if `EventSource` fails (Safari Private mode, some corporate proxies). The TanStack Query `useSeatAvailability` hook switches to SSE by replacing `refetchInterval` with a WebSocket/SSE adapter.

---

## 15. API Compatibility Bridge (M7 Step 7.1)

When the URL renames land (Phase 5 M7), old `/showtimes` and `/sessions` paths should redirect rather than 404:

```go
// Backward-compatible redirects (remove after 3-month deprecation window)
r.GET("/api/v1/showtimes/:id", func(c *gin.Context) {
    c.Redirect(http.StatusMovedPermanently, "/api/v1/screenings/"+c.Param("id"))
})
r.GET("/api/v1/showtimes/:id/seats", func(c *gin.Context) {
    c.Redirect(http.StatusMovedPermanently,
        "/api/v1/screenings/"+c.Param("id")+"/availability?"+c.Request.URL.RawQuery)
})
```

301 (Permanent) so browsers and clients cache the redirect. Remove after the frontend is fully migrated.

---

## 16. Issues in Current API (Cross-reference)

| Current Issue | Location | Severity | Fix |
|---|---|---|---|
| `showtimes`, `sessions` in URLs | Router | Medium | M7 rename + compat redirects |
| No `X-Request-ID` in responses | Middleware | Medium | M6 Step 6.4 |
| `GET /seats` verb `seat` is a collection, name is wrong | Router | Low | M7 rename to `availability` |
| No pagination on `GET /movies` | Handler | Low | M7 Step 7.2 |
| No pagination on `GET /users/:id/bookings` | Handler | Low | M7 Step 7.3 |
| No `Idempotency-Key` support | Handler | Medium | M1 Step 1.4 |
| `allow_origins: *` | Middleware | High (prod) | M6 Step 6.3 (env var) |
| Admin auth hardcoded | Router | Critical | M1 Step 1.2 |
| Error bodies inconsistent (some plain strings) | Handlers | Medium | M7 Step 7.4 |
| No rate limit headers | Middleware | Low | M6 Step 6.5 |
