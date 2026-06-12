import type {
  BookingResponse,
  ErrorResponse,
  HoldResponse,
  Movie,
  PaymentResponse,
  SeatStatus,
  Showtime,
} from "@/types";

const BASE = "/api/v1";

function authHeaders(): Record<string, string> {
  if (typeof window === "undefined") return {};
  const token = localStorage.getItem("cinebook_access_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export class ApiError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status: number
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: body != null ? JSON.stringify(body) : undefined,
    cache: "no-store",
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json();
  if (!res.ok) {
    const err = data as Partial<ErrorResponse>;
    throw new ApiError(
      err.code ?? "UNKNOWN_ERROR",
      err.message ?? `HTTP ${res.status}`,
      res.status
    );
  }
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
    pay: (
      sessionID: string,
      userID: string,
      card: { card_number: string; expiry: string; cvv: string; amount_cents: number; currency: string }
    ) =>
      request<PaymentResponse>("POST", `/sessions/${sessionID}/pay`, {
        user_id: userID,
        ...card,
      }),
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
