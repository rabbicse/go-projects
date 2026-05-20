import type { Movie } from "@/types";

// Shown when the backend is unreachable — lets the UI be visualised without infrastructure.
export const FALLBACK_MOVIES: Movie[] = [
  {
    id: "dune-part-two",
    title: "Dune: Part Two",
    genre: ["Sci-Fi", "Adventure", "Epic"],
    rating: 8.5,
    poster_url: "https://image.tmdb.org/t/p/w500/1pdfLvkbY9ohJlCjQH2CZjjYVvJ.jpg",
    description: "Paul Atreides unites with the Fremen while on a warpath of revenge against the conspirators who destroyed his family.",
    duration_min: 166,
    showtimes: [
      { id: "dune2-hall1-1", movie_id: "dune-part-two", hall: "Hall A", start_time: addHours(2), end_time: addHours(4.77), rows: 8, seats_per_row: 10, total_seats: 80, price_cents: 1500, currency: "USD" },
      { id: "dune2-hall2-1", movie_id: "dune-part-two", hall: "Hall B", start_time: addHours(5), end_time: addHours(7.77), rows: 6, seats_per_row: 8, total_seats: 48, price_cents: 1200, currency: "USD" },
    ],
  },
  {
    id: "oppenheimer",
    title: "Oppenheimer",
    genre: ["Biography", "Drama", "History"],
    rating: 8.9,
    poster_url: "https://image.tmdb.org/t/p/w500/8Gxv8gSFCU0XGDykEGv7zR1n2ua.jpg",
    description: "The story of American scientist J. Robert Oppenheimer and his role in the development of the atomic bomb.",
    duration_min: 180,
    showtimes: [
      { id: "oppen-hall2-1", movie_id: "oppenheimer", hall: "Hall B", start_time: addHours(3), end_time: addHours(6), rows: 6, seats_per_row: 8, total_seats: 48, price_cents: 1400, currency: "USD" },
    ],
  },
  {
    id: "inception",
    title: "Inception",
    genre: ["Sci-Fi", "Action", "Thriller"],
    rating: 8.8,
    poster_url: "https://image.tmdb.org/t/p/w500/oYuLEt3zVCKq57qu2F8dT7NIa6f.jpg",
    description: "A thief who steals corporate secrets through dream-sharing technology is given the inverse task of planting an idea.",
    duration_min: 148,
    showtimes: [
      { id: "inception-hall1-1", movie_id: "inception", hall: "Hall A", start_time: addHours(1), end_time: addHours(3.47), rows: 8, seats_per_row: 10, total_seats: 80, price_cents: 1000, currency: "USD" },
    ],
  },
  {
    id: "the-batman",
    title: "The Batman",
    genre: ["Action", "Crime", "Drama"],
    rating: 7.8,
    poster_url: "https://image.tmdb.org/t/p/w500/74xTEgt7R36Fpooo50r9T25onhq.jpg",
    description: "Batman ventures into Gotham City's underworld when a sadistic killer leaves behind cryptic clues targeting Gotham's elite.",
    duration_min: 176,
    showtimes: [
      { id: "batman-hall2-1", movie_id: "the-batman", hall: "Hall B", start_time: addHours(6), end_time: addHours(8.93), rows: 6, seats_per_row: 8, total_seats: 48, price_cents: 1300, currency: "USD" },
    ],
  },
  {
    id: "interstellar",
    title: "Interstellar",
    genre: ["Sci-Fi", "Adventure", "Drama"],
    rating: 8.6,
    poster_url: "https://image.tmdb.org/t/p/w500/gEU2QniE6E77NI6lCU6MxlNBvIx.jpg",
    description: "A team of explorers travel through a wormhole in space in an attempt to ensure humanity's survival.",
    duration_min: 169,
    showtimes: [
      { id: "inter-hall3-1", movie_id: "interstellar", hall: "Hall C", start_time: addHours(8), end_time: addHours(10.82), rows: 10, seats_per_row: 12, total_seats: 120, price_cents: 1100, currency: "USD" },
    ],
  },
];

function addHours(h: number): string {
  return new Date(Date.now() + h * 3600 * 1000).toISOString();
}
