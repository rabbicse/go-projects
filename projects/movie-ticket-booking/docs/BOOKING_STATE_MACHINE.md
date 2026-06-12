# Booking State Machine

---

## Booking States

A booking record transitions through four states from creation to terminal:

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   ┌──────────┐   HoldSeats    ┌─────────┐   ConfirmBooking    │
│   │  (none)  │ ────────────► │  held   │ ─────────────────►   │
│   └──────────┘                └─────────┘                       │
│                                    │                            │
│                                    │ ReleaseBooking             │
│                                    │ or HOLD_TTL fires          │
│                                    ▼                            │
│                               ┌─────────┐                       │
│                               │released │  (terminal)           │
│                               └─────────┘                       │
│                                                                 │
│                      ConfirmBooking                             │
│                            │                                    │
│                            ▼                                    │
│                       ┌─────────────┐                           │
│                       │  confirmed  │  (terminal)               │
│                       └─────────────┘                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Full State Transition Table

| Current State | Event | Next State | Redis action | MongoDB action |
|---|---|---|---|---|
| — | `HoldSeats` (all seats NX succeed) | `held` | `SET key sessionID NX EX ttl` × N seats + session key | `Save(booking{status:held})` |
| `held` | `ConfirmBooking` (session exists, user matches) | `confirmed` | `PERSIST` all seat keys + session key | `Update(booking{status:confirmed})` |
| `held` | `ReleaseBooking` (user cancels) | `released` | `DEL` all seat keys + session key | `Update(booking{status:released})` |
| `held` | HOLD_TTL fires (Redis expiry) | `released` (implicit) | Keys auto-deleted by Redis | No update (TTL cleanup background job) |
| `confirmed` | `ReleaseBooking` arrives (RC-01) | `confirmed` (unchanged) | `luaRelease` detects TTL=-1, aborts | No change |
| `held` | `ConfirmBooking` after TTL (RC-02) | Error (`SESSION_EXPIRED`) | `luaConfirm` detects `EXISTS`=0, aborts | No write |

### Invalid transitions (rejected at domain layer)

| Attempted | Reason |
|---|---|
| `HoldSeats` on an already-held seat | `ErrSeatAlreadyHeld` — luaHoldSeats returns `SEAT_TAKEN` |
| `ConfirmBooking` by wrong user | `ErrUnauthorized` — session.UserID ≠ requesting userID |
| Hold more than `MAX_SEATS_PER_SESSION` | `ErrMaxSeatsExceeded` — validated in `BookingService` before Redis |

---

## Redis State vs. MongoDB State

These are two independent projections of the same booking. They can temporarily diverge (e.g., Redis TTL fires before MongoDB cleanup), which is why the Lua scripts are the authoritative gate:

| Truth source | Used for |
|---|---|
| Redis seat keys (TTL presence) | Real-time seat availability, concurrent hold prevention |
| MongoDB `bookings` collection | Booking history, user receipts, revenue stats, audit log |

The seat map (`GET /showtimes/:id/seats`) reads from Redis only — it never touches MongoDB. Booking history (`GET /users/:id/bookings`) reads from MongoDB only.

---

## Frontend Stage Machine

The browser mirrors a subset of the booking states with additional UX-only stages:

```
browse ──(click seat)──► checkout ──(proceed)──► paying ──(pay)──► confirmed
          (debounce sync)            (freeze seats)  (card form)
              │                          │
              └──(release all)───────────┘
                       │
                       ▼
                    browse
```

| Stage | Seat clicks | Action buttons | API |
|---|---|---|---|
| `browse` | Enabled | — | Background sync after 300ms debounce |
| `checkout` | Enabled | Proceed, Release All | Background sync after 300ms debounce |
| `paying` | **Disabled** | Pay Now (with card form), Cancel | `POST /sessions/:id/pay` on submit |
| `confirmed` | **Disabled** | — | None |

The frontend `syncing` state (debounce pending or API in flight) temporarily disables the "Proceed to Payment" button to ensure the session state is settled before entering the payment form. This bridges the gap between the instant-feedback seat clicks (Milestone D) and the API-authoritative checkout state.

---

## Session TTL Timeline

```
T+0s    User holds seats          → Redis TTL = HOLD_TTL (default 600s)
T+0s    Frontend countdown starts → shows mm:ss decrementing
T+540s  Frontend timer < 60s      → countdown turns red (urgent)
T+600s  HOLD_TTL fires            → Redis keys deleted, seats become available
T+600s  Frontend detects expiry   → doRelease() called, stage → browse, error shown

Payment window (stage = "paying"):
T+0s    User clicks "Proceed to Payment"
T+0s    Frontend sets payExpiry = now + 180s
T+180s  Payment timer fires       → doRelease() called, stage → browse
```

If the user pays within the payment window (180s < HOLD_TTL remaining), the confirm API persists the hold and the booking is complete.

---

## Error Catalogue

| HTTP status | Code | Cause | Recovery |
|---|---|---|---|
| 409 | `SEAT_ALREADY_HELD` | Seat taken by another user | Re-fetch seat map, pick different seat |
| 410 | `SESSION_EXPIRED` | HOLD_TTL fired before confirm | Re-select seats from scratch |
| 400 | `MAX_SEATS_EXCEEDED` | Requested > 4 seats | Reduce selection |
| 401 | `UNAUTHORIZED` | Session owned by different user | Re-authenticate |
| 402 | `PAYMENT_DECLINED` | Card ending in 0000 (mock gateway) | Try different card |
| 404 | `SESSION_NOT_FOUND` | Session ID not in Redis | Hold expired; re-select |
