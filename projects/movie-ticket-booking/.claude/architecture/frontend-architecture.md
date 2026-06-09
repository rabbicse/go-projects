# Frontend Architecture

_Phase 8 — Frontend modernization design — 2026-06-09_  
_Builds on: frontend-analysis.md (Phase 0), domain-model.md (Phase 2)_

---

## 1. Tech Stack

| Concern | Choice | Version | Replaces |
|---|---|---|---|
| Framework | Next.js App Router | 15.x (current) | — (keep) |
| UI library | React | 19.x (current) | — (keep) |
| Language | TypeScript | 5.x (current) | — (keep) |
| Styling | Tailwind CSS v4 | 4.x | Inline style objects |
| Component library | shadcn/ui | latest | Hand-rolled components |
| Server state | TanStack Query v5 | 5.x | Manual `useEffect` + `setInterval` |
| Forms | React Hook Form + Zod | 7.x / 3.x | Plain HTML validation |
| Validation schemas | Zod | 3.x | None |
| Icons | Lucide React | latest | None |
| Notifications | Sonner (toast) | latest | Inline error divs |

**Why TanStack Query over SWR**: TQ v5 has first-class `refetchIntervalInBackground: false` (pauses polling when tab hidden — fixes TD-21), mutation optimistic updates are simpler, and `invalidateQueries` for cache invalidation after mutations is more ergonomic.

**Why shadcn over Radix direct / MUI / Chakra**: shadcn components are copy-pasted into the project (own the code), built on Radix primitives (accessible), styled with Tailwind (consistent), and have zero runtime dependency. No bundle size overhead from unused components.

**Why Tailwind v4**: CSS-first configuration (no `tailwind.config.js`), native CSS cascade layers, 35% smaller default bundle.

---

## 2. Folder Structure

```
frontend/src/

  app/                                   ← Next.js App Router pages
    layout.tsx                           # Root layout (Providers, fonts)
    page.tsx                             # Home → redirects to /movies
    movies/
      page.tsx                           # Movie list (Server Component)
      [movieId]/
        page.tsx                         # Movie detail (Server Component)
    screenings/
      [screeningId]/
        page.tsx                         # Seat selection (Client Feature)
    bookings/
      page.tsx                           # User booking history (Client)
    admin/
      layout.tsx                         # Admin layout + auth guard
      page.tsx                           # Admin dashboard
      movies/
        page.tsx                         # Movie management table
        new/page.tsx                     # Create movie form
      screenings/
        new/page.tsx                     # Create screening form
    api/                                 # (Next.js API routes if needed)

  features/                              ← Feature modules (business logic)
    catalog/
      components/
        MovieCard.tsx
        MovieGrid.tsx
        ScreeningCard.tsx
        ScreeningList.tsx
      hooks/
        useMovies.ts                     # TanStack Query hooks
        useMovie.ts
        useScreening.ts
      types.ts                           # Feature-local types

    booking/
      components/
        SeatGrid.tsx                     # Seat map (polling, optimistic)
        SeatLegend.tsx
        CheckoutPanel.tsx
        PaymentPanel.tsx
        ConfirmationPanel.tsx
        BookingTimer.tsx                 # Countdown display
        SeatBadge.tsx
      hooks/
        useBookingFlow.ts                # State machine (useReducer)
        useSeatAvailability.ts           # TanStack Query + polling
        useReservation.ts                # Hold / confirm / cancel mutations
        useCountdown.ts
      machine/
        bookingMachine.ts                # State machine definition
        bookingReducer.ts
      types.ts

    admin/
      components/
        MovieForm.tsx                    # React Hook Form + Zod
        ScreeningForm.tsx
        MovieTable.tsx
      hooks/
        useAdminMovies.ts
      schemas/
        movieSchema.ts                   # Zod schemas
        screeningSchema.ts

  components/                            ← Shared UI components
    ui/                                  # shadcn/ui components (generated)
      button.tsx
      card.tsx
      badge.tsx
      dialog.tsx
      skeleton.tsx
      form.tsx
      input.tsx
      table.tsx
      alert.tsx
      toast.tsx
      ...
    layout/
      Header.tsx
      Footer.tsx
      PageContainer.tsx
    common/
      ErrorBoundary.tsx
      LoadingSkeleton.tsx
      EmptyState.tsx
      CountdownTimer.tsx

  lib/
    api/
      client.ts                          # Base fetch client
      catalog.ts                         # Catalog API functions
      booking.ts                         # Booking/reservation API functions
      admin.ts                           # Admin API functions
    queryClient.ts                       # TanStack Query client config
    utils.ts                             # cn(), formatCurrency(), formatDate()

  hooks/
    useUserID.ts                         # localStorage user identity
    useLocalStorage.ts
    useDebounce.ts

  types/
    api.ts                               # API response types (generated from OpenAPI)
    domain.ts                            # Domain types mirroring Go domain model

  providers/
    QueryProvider.tsx                    # TanStack Query provider
    ThemeProvider.tsx                    # (if dark mode toggle added)
```

---

## 3. Server Component vs Client Component Decision Tree

```
Does the component need:
  ├─ useState / useEffect / event handlers?     → Client Component
  ├─ Browser APIs (sessionStorage, window)?     → Client Component
  ├─ TanStack Query hooks?                      → Client Component
  └─ None of the above?                         → Server Component (default)
```

### Server Components (data fetching at render time)

```tsx
// app/movies/page.tsx — Server Component
import { api } from "@/lib/api/catalog";

export default async function MoviesPage() {
  const movies = await api.catalog.listMovies();       // direct fetch, no hooks
  return <MovieGrid movies={movies} />;
}

// app/movies/[movieId]/page.tsx — Server Component
export default async function MovieDetailPage({ params }) {
  const movie = await api.catalog.getMovie(params.movieId);
  return (
    <>
      <MovieHero movie={movie} />
      <ScreeningList screenings={movie.screenings} />
    </>
  );
}
```

**Why Server Components for catalog**: Movie data changes infrequently. Server rendering gives instant First Contentful Paint with no client-side waterfall. No JavaScript sent for the catalog reading path.

### Client Components (interactivity)

```tsx
// features/booking/components/SeatGrid.tsx — "use client"
// features/catalog/components/ScreeningCard.tsx — "use client" (has onClick)
// features/admin/components/MovieForm.tsx — "use client" (React Hook Form)
```

### Hybrid Pattern (default in App Router)

```tsx
// app/screenings/[screeningId]/page.tsx — Server Component shell
import { api } from "@/lib/api/catalog";
import { SeatSelectionFeature } from "@/features/booking/components/SeatSelectionFeature";

export default async function ScreeningPage({ params }) {
  // Fetch static screening data on the server (no loading state needed)
  const screening = await api.catalog.getScreening(params.screeningId);
  
  // Pass to client component for interactive seat selection
  return <SeatSelectionFeature screening={screening} />;
}
```

The screening name, time, price, and seat layout are rendered on the server. The interactive seat grid and booking flow are client-side.

---

## 4. Feature: Catalog

### `features/catalog/hooks/useMovies.ts`

```typescript
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/catalog";

export function useMovies() {
  return useQuery({
    queryKey: ["movies"],
    queryFn: api.catalog.listMovies,
    staleTime: 60_000,     // treat as fresh for 60s
    gcTime: 5 * 60_000,    // keep in cache 5 minutes
  });
}

export function useMovie(movieId: string) {
  return useQuery({
    queryKey: ["movies", movieId],
    queryFn: () => api.catalog.getMovie(movieId),
    staleTime: 60_000,
    enabled: !!movieId,
  });
}

export function useScreening(screeningId: string) {
  return useQuery({
    queryKey: ["screenings", screeningId],
    queryFn: () => api.catalog.getScreening(screeningId),
    staleTime: 30_000,
    enabled: !!screeningId,
  });
}
```

### `features/catalog/components/MovieCard.tsx`

```tsx
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { Movie } from "@/types/domain";
import Image from "next/image";
import Link from "next/link";

interface Props { movie: Movie }

export function MovieCard({ movie }: Props) {
  return (
    <Card className="overflow-hidden hover:shadow-lg transition-shadow">
      <div className="relative aspect-[2/3]">
        <Image src={movie.poster_url} alt={movie.title} fill className="object-cover" />
      </div>
      <CardContent className="p-4">
        <h3 className="font-semibold text-lg leading-tight">{movie.title}</h3>
        <div className="flex items-center gap-2 mt-1 mb-2">
          <span className="text-sm text-muted-foreground">⭐ {movie.rating}</span>
          <span className="text-sm text-muted-foreground">·</span>
          <span className="text-sm text-muted-foreground">{movie.duration_min}m</span>
        </div>
        <div className="flex flex-wrap gap-1">
          {movie.genres.map(g => (
            <Badge key={g} variant="secondary" className="text-xs">{g}</Badge>
          ))}
        </div>
      </CardContent>
      <CardFooter className="p-4 pt-0">
        <Button asChild className="w-full">
          <Link href={`/movies/${movie.id}`}>View Screenings</Link>
        </Button>
      </CardFooter>
    </Card>
  );
}
```

---

## 5. Feature: Booking (Core — Replaces 436-Line God Component)

### Booking State Machine

The current `Stage` type (`browse | checkout | paying | confirmed`) is replaced with a proper discriminated union managed by `useReducer`. This makes the state explicit, transitions type-safe, and the logic testable.

**`features/booking/machine/bookingMachine.ts`**:

```typescript
import type { Reservation } from "@/types/domain";

// States
export type BookingState =
  | { stage: "idle" }
  | { stage: "selecting"; selectedSeats: string[] }
  | { stage: "holding"; selectedSeats: string[] }
  | { stage: "checkout"; reservation: Reservation; selectedSeats: string[] }
  | { stage: "paying";   reservation: Reservation; payExpiresAt: number }
  | { stage: "confirmed"; bookingId: string; seatIDs: string[]; totalCents: number }
  | { stage: "error"; message: string; previousStage: BookingState };

// Events
export type BookingEvent =
  | { type: "SELECT_SEAT";    seatID: string }
  | { type: "DESELECT_SEAT";  seatID: string }
  | { type: "HOLD_SUCCESS";   reservation: Reservation }
  | { type: "HOLD_FAILURE";   message: string }
  | { type: "PROCEED_TO_PAY" }
  | { type: "CONFIRM_SUCCESS"; bookingId: string; totalCents: number }
  | { type: "CONFIRM_FAILURE"; message: string }
  | { type: "CANCEL" }
  | { type: "RESET" };
```

**`features/booking/machine/bookingReducer.ts`**:

```typescript
export function bookingReducer(
  state: BookingState,
  event: BookingEvent,
): BookingState {
  switch (state.stage) {
    case "idle":
      if (event.type === "SELECT_SEAT")
        return { stage: "selecting", selectedSeats: [event.seatID] };
      return state;

    case "selecting":
      if (event.type === "SELECT_SEAT")
        return { ...state, selectedSeats: [...state.selectedSeats, event.seatID] };
      if (event.type === "DESELECT_SEAT")
        return { ...state, selectedSeats: state.selectedSeats.filter(s => s !== event.seatID) };
      if (event.type === "HOLD_SUCCESS")
        return { stage: "checkout", reservation: event.reservation, selectedSeats: state.selectedSeats };
      if (event.type === "HOLD_FAILURE")
        return { stage: "error", message: event.message, previousStage: state };
      if (event.type === "CANCEL")
        return { stage: "idle" };
      return state;

    case "holding":
      if (event.type === "HOLD_SUCCESS")
        return { stage: "checkout", reservation: event.reservation, selectedSeats: [] };
      if (event.type === "HOLD_FAILURE")
        return { stage: "error", message: event.message, previousStage: state };
      return state;

    case "checkout":
      if (event.type === "PROCEED_TO_PAY")
        return { stage: "paying", reservation: state.reservation,
                 payExpiresAt: Math.floor(Date.now() / 1000) + 180 };
      if (event.type === "SELECT_SEAT")
        return { stage: "selecting", selectedSeats: [event.seatID] };
      if (event.type === "CANCEL")
        return { stage: "idle" };
      return state;

    case "paying":
      if (event.type === "CONFIRM_SUCCESS")
        return { stage: "confirmed", bookingId: event.bookingId,
                 seatIDs: state.reservation.seat_ids, totalCents: event.totalCents };
      if (event.type === "CONFIRM_FAILURE")
        return { stage: "error", message: event.message, previousStage: state };
      if (event.type === "CANCEL")
        return { stage: "idle" };
      return state;

    case "error":
      if (event.type === "RESET") return { stage: "idle" };
      return state;

    default:
      return state;
  }
}
```

### `features/booking/hooks/useBookingFlow.ts`

```typescript
"use client";
import { useReducer, useCallback, useEffect, useRef } from "react";
import { bookingReducer } from "../machine/bookingReducer";
import { useReservation } from "./useReservation";
import { useUserID } from "@/hooks/useUserID";
import type { BookingState } from "../machine/bookingMachine";

const MAX_SEATS = parseInt(process.env.NEXT_PUBLIC_MAX_SEATS ?? "4", 10);

export function useBookingFlow(screeningId: string) {
  const [state, dispatch] = useReducer(bookingReducer, { stage: "idle" });
  const userID = useUserID();
  const stateRef = useRef(state);
  stateRef.current = state;

  const { holdMutation, confirmMutation, cancelMutation } = useReservation(screeningId, userID);

  const selectSeat = useCallback((seatID: string) => {
    const s = stateRef.current;
    const selected = s.stage === "selecting" ? s.selectedSeats :
                     s.stage === "checkout"  ? s.reservation.seat_ids : [];
    if (selected.length >= MAX_SEATS) return;

    const next = [...selected, seatID];
    dispatch({ type: "SELECT_SEAT", seatID });

    holdMutation.mutate(next, {
      onSuccess: (reservation) => dispatch({ type: "HOLD_SUCCESS", reservation }),
      onError:   (err) => dispatch({ type: "HOLD_FAILURE", message: err.message }),
    });
  }, [holdMutation]);

  const deselectSeat = useCallback((seatID: string) => {
    const s = stateRef.current;
    const selected = s.stage === "checkout" ? s.reservation.seat_ids : [];
    const next = selected.filter(id => id !== seatID);
    dispatch({ type: "DESELECT_SEAT", seatID });

    if (next.length === 0) {
      if (s.stage === "checkout") cancelMutation.mutate(s.reservation.reservation_id);
      dispatch({ type: "CANCEL" });
      return;
    }
    holdMutation.mutate(next, {
      onSuccess: (reservation) => dispatch({ type: "HOLD_SUCCESS", reservation }),
      onError:   (err) => dispatch({ type: "HOLD_FAILURE", message: err.message }),
    });
  }, [holdMutation, cancelMutation]);

  const confirm = useCallback(() => {
    const s = stateRef.current;
    if (s.stage !== "paying") return;
    confirmMutation.mutate(s.reservation.reservation_id, {
      onSuccess: (booking) => dispatch({
        type: "CONFIRM_SUCCESS", bookingId: booking.id, totalCents: booking.total_cents,
      }),
      onError: (err) => dispatch({ type: "CONFIRM_FAILURE", message: err.message }),
    });
  }, [confirmMutation]);

  const cancel = useCallback(() => {
    const s = stateRef.current;
    if (s.stage === "checkout" || s.stage === "paying") {
      cancelMutation.mutate(s.reservation.reservation_id);
    }
    dispatch({ type: "CANCEL" });
  }, [cancelMutation]);

  // Release on page unload — fixes TD-24 via sendBeacon
  useEffect(() => {
    const handler = () => {
      const s = stateRef.current;
      if ((s.stage === "checkout" || s.stage === "paying")) {
        navigator.sendBeacon(
          `/api/v1/reservations/${s.reservation.reservation_id}`,
          JSON.stringify({ user_id: userID }),
        );
      }
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [userID]);

  return { state, selectSeat, deselectSeat, confirm, cancel,
           isHolding: holdMutation.isPending, isConfirming: confirmMutation.isPending };
}
```

### `features/booking/hooks/useSeatAvailability.ts`

```typescript
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api/booking";

export function useSeatAvailability(screeningId: string, userID: string) {
  return useQuery({
    queryKey: ["screenings", screeningId, "availability", userID],
    queryFn: () => api.booking.getAvailability(screeningId, userID),
    refetchInterval: 2000,
    refetchIntervalInBackground: false, // pauses when tab hidden — fixes TD-21
    staleTime: 0,                       // always refetch
  });
}
```

### `features/booking/hooks/useReservation.ts`

```typescript
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/booking";

export function useReservation(screeningId: string, userID: string) {
  const queryClient = useQueryClient();

  const holdMutation = useMutation({
    mutationFn: (seatIDs: string[]) =>
      api.booking.reserveSeats(screeningId, userID, seatIDs),
    onSuccess: () => {
      // Invalidate seat availability so the grid reflects the hold immediately
      queryClient.invalidateQueries({
        queryKey: ["screenings", screeningId, "availability"],
      });
    },
  });

  const confirmMutation = useMutation({
    mutationFn: (reservationId: string) =>
      api.booking.confirmReservation(reservationId, userID),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["screenings", screeningId, "availability"] });
      queryClient.invalidateQueries({ queryKey: ["users", userID, "bookings"] });
    },
  });

  const cancelMutation = useMutation({
    mutationFn: (reservationId: string) =>
      api.booking.cancelReservation(reservationId, userID),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["screenings", screeningId, "availability"],
      });
    },
  });

  return { holdMutation, confirmMutation, cancelMutation };
}
```

### `features/booking/hooks/useCountdown.ts`

```typescript
import { useState, useEffect } from "react";

export function useCountdown(expiresAt: number | null) {
  const [remaining, setRemaining] = useState(0);

  useEffect(() => {
    if (!expiresAt) return;
    const update = () => setRemaining(Math.max(0, expiresAt - Math.floor(Date.now() / 1000)));
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [expiresAt]);

  const minutes = Math.floor(remaining / 60);
  const seconds = remaining % 60;
  const display = `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  const isUrgent = remaining < 60 && remaining > 0;
  const isExpired = remaining === 0 && expiresAt !== null;

  return { remaining, display, isUrgent, isExpired };
}
```

### Decomposed `SeatGrid.tsx`

The 436-line god component becomes a thin orchestrator:

```tsx
// app/screenings/[screeningId]/page.tsx (Server Component shell)
import { api } from "@/lib/api/catalog";
import { SeatSelectionFeature } from "@/features/booking/components/SeatSelectionFeature";

export default async function ScreeningPage({ params }: { params: Promise<{ screeningId: string }> }) {
  const { screeningId } = await params;
  const screening = await api.catalog.getScreening(screeningId);
  return <SeatSelectionFeature screening={screening} />;
}
```

```tsx
// features/booking/components/SeatSelectionFeature.tsx  ("use client")
export function SeatSelectionFeature({ screening }: { screening: Screening }) {
  const userID = useUserID();
  const { state, selectSeat, deselectSeat, confirm, cancel, isHolding, isConfirming }
    = useBookingFlow(screening.id);
  const { data: availability } = useSeatAvailability(screening.id, userID);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[1fr_280px] gap-8">
      <SeatGrid
        screening={screening}
        availability={availability ?? []}
        selectedSeats={
          state.stage === "checkout" || state.stage === "paying"
            ? state.reservation.seat_ids
            : state.stage === "selecting" ? state.selectedSeats : []
        }
        onSelect={selectSeat}
        onDeselect={deselectSeat}
        interactive={state.stage !== "paying" && state.stage !== "confirmed"}
        disabled={isHolding}
      />
      <BookingSidebar
        state={state}
        screening={screening}
        onProceedToPayment={() => dispatch({ type: "PROCEED_TO_PAY" })}
        onConfirm={confirm}
        onCancel={cancel}
        isConfirming={isConfirming}
      />
    </div>
  );
}
```

Each panel is now its own component:
- `CheckoutPanel.tsx` — renders when `state.stage === "checkout"`
- `PaymentPanel.tsx` — renders when `state.stage === "paying"`
- `ConfirmationPanel.tsx` — renders when `state.stage === "confirmed"`

---

## 6. Feature: Admin

### Zod Schemas

**`features/admin/schemas/movieSchema.ts`**:

```typescript
import { z } from "zod";

export const createMovieSchema = z.object({
  id: z.string().min(3).max(50).regex(/^[a-z0-9-]+$/, "Lowercase letters, numbers, hyphens only"),
  title: z.string().min(1).max(200),
  genres: z.array(z.string()).min(1, "At least one genre required"),
  rating: z.number().min(0).max(10),
  poster_url: z.string().url("Must be a valid URL"),
  description: z.string().min(10).max(1000),
  duration_min: z.number().int().min(1).max(600),
});

export type CreateMovieFormData = z.infer<typeof createMovieSchema>;
```

**`features/admin/schemas/screeningSchema.ts`**:

```typescript
import { z } from "zod";

export const createScreeningSchema = z.object({
  id: z.string().min(3).max(80),
  movie_id: z.string().min(1),
  screen: z.string().min(1).max(50),
  start_time: z.string().datetime(),
  end_time: z.string().datetime(),
  rows: z.number().int().min(1).max(26),
  seats_per_row: z.number().int().min(1).max(30),
  price_cents: z.number().int().min(100),
  currency: z.string().length(3).default("USD"),
}).refine(
  (d) => new Date(d.end_time) > new Date(d.start_time),
  { message: "End time must be after start time", path: ["end_time"] }
);
```

### `features/admin/components/MovieForm.tsx`

```tsx
"use client";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage }
  from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { createMovieSchema, type CreateMovieFormData } from "../schemas/movieSchema";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api/admin";
import { toast } from "sonner";

export function MovieForm() {
  const queryClient = useQueryClient();
  const form = useForm<CreateMovieFormData>({
    resolver: zodResolver(createMovieSchema),
    defaultValues: { rating: 7.0, genres: [], duration_min: 120 },
  });

  const mutation = useMutation({
    mutationFn: api.admin.createMovie,
    onSuccess: () => {
      toast.success("Movie created successfully");
      queryClient.invalidateQueries({ queryKey: ["movies"] });
      form.reset();
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(d => mutation.mutate(d))} className="space-y-4">
        <FormField control={form.control} name="title" render={({ field }) => (
          <FormItem>
            <FormLabel>Title</FormLabel>
            <FormControl><Input placeholder="Movie title" {...field} /></FormControl>
            <FormMessage />
          </FormItem>
        )} />
        {/* ... other fields */}
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Creating…" : "Create Movie"}
        </Button>
      </form>
    </Form>
  );
}
```

---

## 7. API Layer

### `lib/api/client.ts`

```typescript
const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

export async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const res = await fetch(`${BASE_URL}/api/v1${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body != null ? JSON.stringify(body) : undefined,
    signal,
    cache: "no-store",
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json();
  if (!res.ok) throw new ApiError(res.status, data.error ?? `HTTP ${res.status}`);
  return data as T;
}
```

### `lib/api/booking.ts`

```typescript
import { request } from "./client";
import type { Reservation, Booking, SeatAvailability } from "@/types/api";

export const booking = {
  reserveSeats: (screeningId: string, userID: string, seatIDs: string[]) =>
    request<Reservation>("POST", `/screenings/${screeningId}/reservations`, {
      user_id: userID, seat_ids: seatIDs,
    }),

  confirmReservation: (reservationId: string, userID: string) =>
    request<Booking>("PUT", `/reservations/${reservationId}/confirm`, { user_id: userID }),

  cancelReservation: (reservationId: string, userID: string) =>
    request<void>("DELETE", `/reservations/${reservationId}`, { user_id: userID }),

  getAvailability: (screeningId: string, userID?: string) =>
    request<SeatAvailability[]>(
      "GET",
      `/screenings/${screeningId}/availability${userID ? `?user_id=${userID}` : ""}`,
    ),

  getUserBookings: (userID: string, page = 1, pageSize = 20) =>
    request<{ bookings: Booking[]; total: number }>(
      "GET", `/users/${userID}/bookings?page=${page}&page_size=${pageSize}`,
    ),
};
```

---

## 8. User Identity

Current: `sessionStorage` → lost on tab refresh, different per tab. Fix: `localStorage`.

**`hooks/useUserID.ts`**:

```typescript
import { useState, useEffect } from "react";

const KEY = "cinebook_user_id";

function generateUserID(): string {
  return crypto.randomUUID(); // full UUID, not truncated
}

export function useUserID(): string {
  const [userID, setUserID] = useState<string>("");

  useEffect(() => {
    // Read from localStorage (persists across refreshes)
    let id = localStorage.getItem(KEY);
    if (!id) {
      id = generateUserID();
      localStorage.setItem(KEY, id);
    }
    setUserID(id);
  }, []);

  return userID;
}
```

**Fixes**: TD-24 (user identity lost on refresh), SM-17 (sessionStorage per-tab).

---

## 9. TanStack Query Configuration

**`lib/queryClient.ts`**:

```typescript
import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./api/client";

export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        retry: (failureCount, error) => {
          // Don't retry 4xx errors (client errors)
          if (error instanceof ApiError && error.status < 500) return false;
          return failureCount < 2;
        },
        refetchOnWindowFocus: true,
        refetchOnReconnect: true,
      },
      mutations: {
        retry: false, // Never retry mutations
      },
    },
  });
}
```

**`providers/QueryProvider.tsx`**:

```tsx
"use client";
import { useState } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { createQueryClient } from "@/lib/queryClient";

export function QueryProvider({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(createQueryClient);
  return (
    <QueryClientProvider client={queryClient}>
      {children}
      {process.env.NODE_ENV === "development" && <ReactQueryDevtools />}
    </QueryClientProvider>
  );
}
```

### Query Key Factory

```typescript
// lib/queryKeys.ts — centralised query key definitions
export const queryKeys = {
  movies: {
    all: () => ["movies"] as const,
    detail: (id: string) => ["movies", id] as const,
  },
  screenings: {
    detail: (id: string) => ["screenings", id] as const,
    availability: (id: string, userID: string) =>
      ["screenings", id, "availability", userID] as const,
  },
  users: {
    bookings: (userId: string, page: number) =>
      ["users", userId, "bookings", page] as const,
  },
} as const;
```

---

## 10. Shadcn Component Inventory

Components to install and use:

| Component | Used By | Install Command |
|---|---|---|
| `button` | All features | `npx shadcn@latest add button` |
| `card` | MovieCard, BookingSidebar, ConfirmationPanel | `add card` |
| `badge` | Genre tags, SeatBadge | `add badge` |
| `dialog` | Checkout panel on mobile | `add dialog` |
| `skeleton` | Loading states for MovieGrid, SeatGrid | `add skeleton` |
| `form` | Admin forms | `add form` |
| `input` | Admin forms, search | `add input` |
| `table` | Admin movie list | `add table` |
| `alert` | Error states | `add alert` |
| `progress` | Countdown timer bar | `add progress` |
| `separator` | Layout dividers | `add separator` |
| `toast` (Sonner) | Success/error notifications | `add sonner` |

---

## 11. Error Boundary

**`components/common/ErrorBoundary.tsx`**:

```tsx
"use client";
import { Component, type ReactNode } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

interface Props { children: ReactNode; fallback?: ReactNode }
interface State { error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    if (this.state.error) {
      return this.props.fallback ?? (
        <Alert variant="destructive" className="m-4">
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{this.state.error.message}</AlertDescription>
          <Button className="mt-2" onClick={() => this.setState({ error: null })}>
            Try again
          </Button>
        </Alert>
      );
    }
    return this.props.children;
  }
}
```

Wrap feature roots in the app layout:
```tsx
<ErrorBoundary>
  <SeatSelectionFeature screening={screening} />
</ErrorBoundary>
```

---

## 12. Migration Plan from Current Frontend

| Step | What | Risk | Effort |
|---|---|---|---|
| F-01 | Install Tailwind v4, shadcn, TanStack Query, Zod, RHF | 🟢 Low | 1h |
| F-02 | Create `lib/queryClient.ts` + `providers/QueryProvider.tsx` | 🟢 Low | 30m |
| F-03 | Create `hooks/useUserID.ts` (localStorage) | 🟢 Low | 30m |
| F-04 | Migrate `lib/api.ts` → `lib/api/{catalog,booking,admin}.ts` | 🟢 Low | 1h |
| F-05 | Create feature folder structure (empty files) | 🟢 Low | 30m |
| F-06 | Extract `useCountdown`, `useSeatAvailability` from `ShowtimePage` | 🟡 Med | 1h |
| F-07 | Build booking state machine + `useBookingFlow` | 🟡 Med | 2h |
| F-08 | Decompose `ShowtimePage` into `SeatSelectionFeature` + panels | 🟠 High | 3h |
| F-09 | Migrate `MovieCard`, `ShowtimeCard` to Tailwind + shadcn | 🟡 Med | 1h |
| F-10 | Rewrite `SeatGrid.tsx` with TanStack Query | 🟡 Med | 1h |
| F-11 | Add `ErrorBoundary` wrapper | 🟢 Low | 30m |
| F-12 | Rewrite admin pages with React Hook Form + Zod | 🟡 Med | 2h |
| F-13 | Add loading skeletons (Skeleton components) | 🟢 Low | 1h |
| F-14 | Add `Sonner` toasts, replace inline error divs | 🟢 Low | 30m |
| F-15 | Update `next.config.ts` with new API route rewrites | 🟢 Low | 30m |

**Total estimated effort**: ~16 hours.

**Migration order**: F-01 → F-04 → F-02 → F-03 → F-05 → F-07 → F-08 → F-06 → F-09 → F-10 → rest  
The state machine (F-07) must come before decomposing the God Component (F-08).

---

## 13. What the Modernized Frontend Fixes

| Issue | Current | Target |
|---|---|---|
| TD-22 God component (436 lines) | Single file | `useBookingFlow` + 4 panel components |
| TD-23 No state management | Manual `useState` + `setInterval` | TanStack Query + `useReducer` |
| TD-21 Unconditional polling | Every 2s including hidden tabs | `refetchIntervalInBackground: false` |
| TD-24 sessionStorage user ID | Lost on refresh | localStorage, full UUID |
| TD-25 PAYMENT_TTL_S magic number | Hardcoded 180 | Derived from reservation `expires_at` |
| TD-27 Zero frontend tests | None | Vitest + React Testing Library |
| TD-28 No error boundaries | Silent crashes | `ErrorBoundary` at feature root |
| SM-16 Unconditional polling | Always on | Paused when tab hidden |
| SM-17 sessionStorage → tab isolated | Different IDs per tab | localStorage — shared across tabs |
| SEC-04 Admin auth in localStorage | Credentials stored | Proper httpOnly cookie flow |
