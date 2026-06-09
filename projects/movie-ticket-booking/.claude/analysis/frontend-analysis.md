# Frontend Analysis

_Based on full source read of `frontend/src/` — 2026-06-08_

## Structure

```
src/
├── app/
│   ├── page.tsx                          # Movie list (Server Component)
│   ├── layout.tsx                        # Root layout
│   ├── globals.css                       # CSS custom properties
│   ├── movies/[movieId]/page.tsx         # Movie detail (Server Component)
│   ├── showtimes/[showtimeId]/page.tsx   # Seat selection (Client Component — 436 lines)
│   └── admin/
│       ├── page.tsx                      # Admin dashboard
│       ├── login/page.tsx                # Admin login (localStorage-based)
│       └── movies/new/page.tsx           # Create movie form
├── components/
│   ├── SeatGrid.tsx                      # Polling grid, 2s interval
│   ├── MovieCard.tsx
│   ├── ShowtimeCard.tsx
│   ├── Checkout.tsx                      # (exists but not used by showtimePage directly)
│   ├── Timer.tsx
│   └── UserBadge.tsx
├── lib/
│   ├── api.ts                            # Typed fetch wrapper
│   └── fallback-data.ts                  # Static fallback for dev/SSR
└── types/index.ts                        # Shared TypeScript types
```

## Component Analysis

### `app/page.tsx` and `movies/[movieId]/page.tsx` — Server Components

- Use `cache: "no-store"` fetch — appropriate for real-time seat availability.
- Simple data-fetch + render. No state. Correct use of Server Components.

### `app/showtimes/[showtimeId]/page.tsx` — Client Component (God Component)

This is the core UI. **436 lines** in a single component managing:
- Showtime data fetching
- Seat selection state
- Session/hold lifecycle (`reHold`, `doRelease`, `doConfirm`)
- Stage machine (`browse → checkout → paying → confirmed`)
- 1-second countdown heartbeat
- Auto-release timer effects (hold expiry + payment expiry)
- `beforeunload` handler for session cleanup via `sendBeacon`
- All inline UI rendering (Panel, Btn, InfoRow, Countdown primitives defined inside the file)

This component violates Single Responsibility and is difficult to test.

### `SeatGrid.tsx` — Client Component

- Polls `/api/v1/showtimes/:id/seats` every **2 seconds unconditionally** — regardless of whether the user is active or the seats have changed.
- Implements optimistic UI: `selectedSeats` prop overrides server state visually.
- `fetchStatuses` is memoised with `useCallback` but `setStatuses` triggers a full re-render every 2 seconds.
- No exponential back-off or polling pause on error.

## State Management

No state management library. All state lives in `useState` inside `ShowtimePage`. The component uses `useRef` for `sessionRef` to access session inside `beforeunload` (correct pattern for stale closures).

**Problems:**
- No shared state between pages (e.g., user identity leaks: `sessionStorage` only, not shared with server)
- No caching layer — each navigation re-fetches from scratch
- No server state synchronisation (TanStack Query/SWR would handle stale-while-revalidate)

## API Client (`lib/api.ts`)

Clean typed wrapper over `fetch`. Namespaced by resource (`api.movies`, `api.showtimes`, `api.sessions`, `api.users`). Uses `/api/v1` base URL — relies on Next.js rewrites to proxy to backend.

**Issue**: No retry logic. A single network blip causes a visible error. No request cancellation on component unmount (no `AbortController`).

## Styling

Pure CSS custom properties defined in `globals.css`. Inline style objects throughout. No Tailwind, no CSS modules, no component library.

**Assessment**: Works for a demo. Not scalable — large components have dozens of inline style objects. Theming is done through CSS variables (good). But refactoring styles is painful.

## User Identity

```typescript
const id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
sessionStorage.setItem("cinebook_user_id", id);
```

- UUID truncated to 12 chars — collision probability ~1 in 16^12 ≈ negligible but non-zero.
- `sessionStorage` is per-tab: refreshing the page creates a new identity, losing booking history.
- Not persistent across tabs — opening the site in two tabs gives two different user IDs.
- No authentication, no server-side user record.

## Admin Pages

- `admin/login/page.tsx` stores credentials in `localStorage` — pure client-side "auth".
- Calls the backend admin endpoints which are protected by HTTP Basic Auth.
- No CSRF protection.

## Payment Simulation

The "payment" stage is entirely fictional:
- A 3-minute countdown is started (`PAYMENT_TTL_S = 180`)
- "Pay Now" button immediately calls the confirm endpoint
- No actual payment processing

This is intentional for a demo, but should be called out explicitly in documentation.

## Missing Capabilities

| Capability | Status |
|---|---|
| TanStack Query / SWR | Absent — manual polling + useEffect |
| Form validation (Zod / react-hook-form) | Absent — basic HTML validation only |
| Error boundaries | Absent — errors crash silently |
| Loading skeletons | Absent — plain "Loading…" text |
| Accessibility (ARIA) | Minimal — buttons have `title` attr only |
| Responsive layout | Basic — flexWrap used, no breakpoints |
| Dark mode | CSS vars support it, but no toggle |
| Test coverage | Zero frontend tests |
| Storybook / component isolation | Absent |
| i18n | Absent |

## Next.js Configuration

- Uses `rewrites()` in `next.config.ts` to proxy `/api/v1/*` to the backend (`NEXT_PUBLIC_API_URL`).
- `NEXT_PUBLIC_MAX_SEATS` propagated to client for UI limit enforcement.
- No custom `headers()` for security headers (CSP, HSTS, etc.).

## Strengths Worth Preserving

1. **Optimistic seat selection** — seat turns gold before API responds, then reverts on error.
2. **`sendBeacon` on beforeunload** — frees seats when user closes tab. Clever.
3. **Dual countdown system** — hold TTL and payment TTL are separate timers. Correct.
4. **`useRef` for stale closure fix** — `sessionRef.current` inside event handler is correct Go-to pattern.
5. **Type-safe API client** — `api.ts` is generic and clean.
