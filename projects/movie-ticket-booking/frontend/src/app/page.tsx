import Image from "next/image";
import Link from "next/link";
import { Star, Clock, Ticket } from "lucide-react";
import { api } from "@/lib/api";
import { FALLBACK_MOVIES } from "@/lib/fallback-data";
import { MovieCard } from "@/components/MovieCard";
import type { Movie } from "@/types";

export const revalidate = 60;

function formatPrice(cents: number, currency: string) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency, minimumFractionDigits: 0 }).format(cents / 100);
}

export default async function HomePage() {
  let movies: Movie[] = [];
  let usingFallback = false;
  try {
    movies = await api.movies.list();
    if (!movies?.length) throw new Error("empty");
  } catch {
    movies = FALLBACK_MOVIES;
    usingFallback = true;
  }

  const featured = movies[0];
  const rest = movies.slice(1);

  return (
    <div>
      {/* Fallback notice */}
      {usingFallback && (
        <div
          className="mb-6 px-4 py-2.5 rounded-lg text-xs flex items-center gap-2"
          style={{ background: "var(--surface-2)", color: "var(--text-muted)", border: "1px solid var(--border)" }}
        >
          <span style={{ color: "var(--warning)" }}>●</span>
          Showing demo data — start the backend at <code className="mx-1 px-1 rounded" style={{ background: "var(--surface-3)" }}>localhost:8080</code> to see live showtimes.
        </div>
      )}

      {/* ── Hero / Featured movie ─────────────────────────────────────────── */}
      {featured && (
        <div className="relative rounded-2xl overflow-hidden mb-12" style={{ minHeight: "420px" }}>
          {/* Backdrop image */}
          {featured.poster_url && (
            <div className="absolute inset-0">
              <Image
                src={featured.poster_url}
                alt={featured.title}
                fill
                className="object-cover object-top"
                sizes="100vw"
                priority
              />
              <div
                className="absolute inset-0"
                style={{
                  background: "linear-gradient(90deg, rgba(8,8,15,0.97) 30%, rgba(8,8,15,0.7) 60%, rgba(8,8,15,0.4) 100%)",
                }}
              />
            </div>
          )}

          {/* Content */}
          <div className="relative z-10 p-8 sm:p-12 flex flex-col justify-end h-full" style={{ minHeight: "420px" }}>
            <div className="max-w-xl">
              <div
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold mb-4"
                style={{ background: "var(--accent)", color: "#fff" }}
              >
                <Ticket size={11} />
                Featured Now
              </div>
              <h1 className="text-4xl sm:text-5xl font-bold mb-3 leading-tight" style={{ color: "#fff" }}>
                {featured.title}
              </h1>
              <div className="flex flex-wrap items-center gap-3 mb-4">
                <div className="flex items-center gap-1 text-sm font-semibold" style={{ color: "var(--warning)" }}>
                  <Star size={14} fill="currentColor" />
                  {featured.rating.toFixed(1)}
                </div>
                <div className="flex items-center gap-1 text-sm" style={{ color: "rgba(255,255,255,0.6)" }}>
                  <Clock size={13} />
                  {featured.duration_min} min
                </div>
                {featured.genre.slice(0, 3).map((g) => (
                  <span
                    key={g}
                    className="text-xs px-2 py-0.5 rounded-full"
                    style={{ background: "rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.7)" }}
                  >
                    {g}
                  </span>
                ))}
              </div>
              <p className="text-sm leading-relaxed mb-6 max-w-md" style={{ color: "rgba(255,255,255,0.65)" }}>
                {featured.description}
              </p>
              <div className="flex items-center gap-3 flex-wrap">
                {featured.showtimes?.slice(0, 1).map((st) => (
                  <Link
                    key={st.id}
                    href={`/showtimes/${st.id}`}
                    className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold text-sm no-underline transition-all hover:opacity-90"
                    style={{ background: "var(--accent)", color: "#fff" }}
                  >
                    <Ticket size={16} />
                    Book {st.hall}
                    {st.price_cents > 0 && (
                      <span className="opacity-75">· {formatPrice(st.price_cents, st.currency)}</span>
                    )}
                  </Link>
                ))}
                <Link
                  href={`/movies/${featured.id}`}
                  className="px-5 py-2.5 rounded-xl font-semibold text-sm no-underline transition-all hover:opacity-80"
                  style={{ background: "rgba(255,255,255,0.1)", color: "#fff", border: "1px solid rgba(255,255,255,0.2)" }}
                >
                  View all showtimes
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Now Playing grid ─────────────────────────────────────────────── */}
      <h2 className="text-xl font-bold mb-5" style={{ color: "var(--text)" }}>
        Now Playing
      </h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-5">
        {rest.map((movie) => (
          <MovieCard key={movie.id} movie={movie} />
        ))}
        {featured && <MovieCard movie={featured} />}
      </div>
    </div>
  );
}
