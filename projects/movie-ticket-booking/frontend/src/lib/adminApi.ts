import { getAccessToken } from "@/lib/auth";
import type { Movie, Theater, Screen, Show } from "@/types";

// adminHeaders returns JSON + Bearer auth headers.
// Server-side calls get no auth header (localStorage unavailable).
export function adminHeaders(): Record<string, string> {
  if (typeof window === "undefined") return { "Content-Type": "application/json" };
  const token = getAccessToken();
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

export async function adminFetch(url: string, options: RequestInit = {}): Promise<Response> {
  return fetch(url, {
    ...options,
    headers: { ...adminHeaders(), ...((options.headers as Record<string, string>) ?? {}) },
  });
}

// ── Error type ────────────────────────────────────────────────────────────────

export class AdminApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code?: string,
  ) {
    super(message);
    this.name = "AdminApiError";
  }
}

// ── Typed JSON request ────────────────────────────────────────────────────────

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await adminFetch(`/api/v1${path}`, {
    method,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    throw new AdminApiError(
      res.status,
      (data.message as string | undefined) ?? `HTTP ${res.status}`,
      data.code as string | undefined,
    );
  }
  return data as T;
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface MovieInput {
  title: string;
  genre: string[];
  rating: number;
  duration_min: number;
  description?: string;
  poster_url?: string;
}

// ── Movie admin API ───────────────────────────────────────────────────────────

export const adminMovies = {
  list: (): Promise<Movie[]> =>
    req<Movie[]>("GET", "/admin/movies"),

  create: (input: MovieInput): Promise<Movie> =>
    req<Movie>("POST", "/admin/movies", { id: crypto.randomUUID(), ...input }),

  update: (id: string, input: MovieInput): Promise<Movie> =>
    req<Movie>("PUT", `/admin/movies/${id}`, input),

  remove: (id: string): Promise<void> =>
    req<void>("DELETE", `/admin/movies/${id}`),

  publish: (id: string): Promise<Movie> =>
    req<Movie>("PUT", `/admin/movies/${id}/publish`),

  unpublish: (id: string): Promise<Movie> =>
    req<Movie>("PUT", `/admin/movies/${id}/unpublish`),

  // Poster upload uses multipart/form-data — do NOT send Content-Type header
  // (browser sets it automatically with the correct boundary).
  uploadPoster: async (id: string, file: File): Promise<{ poster_url: string }> => {
    const token = getAccessToken();
    const form = new FormData();
    form.append("poster", file);
    const res = await fetch(`/api/v1/admin/movies/${id}/poster`, {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: form,
    });
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      throw new AdminApiError(
        res.status,
        (data.message as string | undefined) ?? `HTTP ${res.status}`,
        data.code as string | undefined,
      );
    }
    return data as { poster_url: string };
  },
};

// ── Theater admin API ─────────────────────────────────────────────────────────

export interface TheaterInput {
  name: string;
  location: string;
}

export interface RowCategoryInput {
  row: string;
  category: "standard" | "premium" | "vip";
}

export interface ScreenInput {
  name: string;
  rows_count: number;
  seats_per_row: number;
  row_categories?: RowCategoryInput[];
}

export const adminTheaters = {
  list: (): Promise<Theater[]> =>
    req<Theater[]>("GET", "/admin/theaters"),

  create: (input: TheaterInput): Promise<Theater> =>
    req<Theater>("POST", "/admin/theaters", { id: crypto.randomUUID(), ...input }),

  update: (id: string, input: TheaterInput): Promise<Theater> =>
    req<Theater>("PUT", `/admin/theaters/${id}`, input),

  disable: (id: string): Promise<Theater> =>
    req<Theater>("PUT", `/admin/theaters/${id}/disable`),

  listScreens: (theaterId: string): Promise<Screen[]> =>
    req<Screen[]>("GET", `/admin/theaters/${theaterId}/screens`),

  createScreen: (theaterId: string, input: ScreenInput): Promise<Screen> =>
    req<Screen>("POST", `/admin/theaters/${theaterId}/screens`, {
      id: crypto.randomUUID(),
      ...input,
    }),

  updateScreen: (theaterId: string, screenId: string, input: ScreenInput): Promise<Screen> =>
    req<Screen>("PUT", `/admin/theaters/${theaterId}/screens/${screenId}`, input),

  disableScreen: (theaterId: string, screenId: string): Promise<Screen> =>
    req<Screen>("PUT", `/admin/theaters/${theaterId}/screens/${screenId}/disable`),
};

// ── Show admin API ────────────────────────────────────────────────────────────

export interface ShowInput {
  movie_id: string;
  screen_id: string;
  start_time: string;
  end_time: string;
}

export const adminShows = {
  list: (): Promise<Show[]> =>
    req<Show[]>("GET", "/admin/shows"),

  create: (input: ShowInput): Promise<Show> =>
    req<Show>("POST", "/admin/shows", { id: crypto.randomUUID(), ...input }),

  update: (id: string, input: ShowInput): Promise<Show> =>
    req<Show>("PUT", `/admin/shows/${id}`, input),

  cancel: (id: string): Promise<Show> =>
    req<Show>("PUT", `/admin/shows/${id}/cancel`),
};
