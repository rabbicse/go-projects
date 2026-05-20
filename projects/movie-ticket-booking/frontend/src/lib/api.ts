import type {
  BookingResponse,
  HoldResponse,
  Movie,
  SeatStatus,
  Showtime,
} from "@/types";

const BASE = "/api/v1";

async function request<T>(
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body != null ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
  return data as T;
}

export const api = {
  movies: {
    list: () => request<Movie[]>("GET", "/movies"),
    get: (id: string) => request<Movie>("GET", `/movies/${id}`),
  },

  showtimes: {
    get: (id: string) => request<Showtime>("GET", `/showtimes/${id}`),
    seats: (showtimeId: string, userID?: string) =>
      request<SeatStatus[]>(
        "GET",
        `/showtimes/${showtimeId}/seats${userID ? `?user_id=${userID}` : ""}`
      ),
    hold: (showtimeId: string, userID: string, seatIDs: string[]) =>
      request<HoldResponse>("POST", `/showtimes/${showtimeId}/hold`, {
        user_id: userID,
        seat_ids: seatIDs,
      }),
  },

  sessions: {
    confirm: (sessionID: string, userID: string) =>
      request<BookingResponse>("PUT", `/sessions/${sessionID}/confirm`, {
        user_id: userID,
      }),
    release: (sessionID: string, userID: string) =>
      request<void>("DELETE", `/sessions/${sessionID}`, { user_id: userID }),
  },

  users: {
    bookings: (userID: string) =>
      request<BookingResponse[]>("GET", `/users/${userID}/bookings`),
  },
};
