export interface Movie {
  id: string;
  title: string;
  genre: string[];
  rating: number;
  poster_url: string;
  description: string;
  duration_min: number;
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
}

export interface ActiveSession {
  sessionID: string;
  showtimeID: string;
  movieID: string;
  seatIDs: string[];
  expiresAt: number; // unix timestamp
}
