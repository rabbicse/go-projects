export interface Movie {
  id: string;
  title: string;
  genre: string[];
  rating: number;
  poster_url: string;
  description: string;
  duration_min: number;
  published: boolean;
  created_at?: string;
  updated_at?: string;
  showtimes: Showtime[];
}

export interface Showtime {
  id: string;
  movie_id: string;
  hall: string;
  start_time: string;
  end_time: string;
  rows: number;
  seats_per_row: number;
  total_seats: number;
  price_cents: number;
  currency: string;
}

export interface SeatStatus {
  seat_id: string;
  status: "available" | "held" | "confirmed";
  held_by_me: boolean;
  expires_at?: number; // seconds remaining
}

export interface HoldResponse {
  session_id: string;
  showtime_id: string;
  movie_id: string;
  seat_ids: string[];
  status: string;
  expires_at: number; // unix timestamp
}

export interface BookingResponse {
  id: string;
  session_id: string;
  user_id: string;
  showtime_id: string;
  movie_id: string;
  seats: { id: string; row: string; number: number }[];
  status: string;
  total_cents: number;
  currency: string;
  created_at: string;
  confirmed_at?: string;
  // Enrichment fields — present when the backend can resolve showtime/movie metadata.
  movie_title?: string;
  hall?: string;
  start_time?: string;
  end_time?: string;
}

export interface ActiveSession {
  sessionID: string;
  showtimeID: string;
  movieID: string;
  seatIDs: string[];
  expiresAt: number; // unix timestamp
}

export interface PaymentResponse {
  payment_id: string;
  status: "completed" | "failed";
  booking: BookingResponse;
}

export interface ErrorResponse {
  code: string;
  message: string;
}

export interface Theater {
  id: string;
  name: string;
  location: string;
  status: "active" | "disabled";
  created_at: string;
  updated_at: string;
}

export interface Seat {
  id: string;
  row: string;
  number: number;
  category: "standard" | "premium" | "vip";
}

export interface Screen {
  id: string;
  theater_id: string;
  name: string;
  capacity: number;
  seats: Seat[];
  status: "active" | "disabled";
  created_at: string;
  updated_at: string;
}

export interface Show {
  id: string;
  movie_id: string;
  screen_id: string;
  start_time: string;
  end_time: string;
  status: "scheduled" | "cancelled";
  created_at: string;
  updated_at: string;
}
