import Image from "next/image";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Star, Clock, ChevronLeft } from "lucide-react";
import { api } from "@/lib/api";
import { FALLBACK_MOVIES } from "@/lib/fallback-data";
import { ShowtimeCard } from "@/components/ShowtimeCard";
import type { Movie } from "@/types";

export const revalidate = 30;

interface Props {
  params: Promise<{ movieId: string }>;
}

export default async function MoviePage({ params }: Props) {
  const { movieId } = await params;

  let movie: Movie | undefined;
  try {
    movie = await api.movies.get(movieId);
  } catch {
    movie = FALLBACK_MOVIES.find((m) => m.id === movieId);
  }
  if (!movie) notFound();

  return (
    <div>
      {/* Back */}
      <Link
        href="/"
        className="inline-flex items-center gap-1.5 text-sm mb-6 no-underline transition-colors hover:opacity-80"
        style={{ color: "var(--text-muted)" }}
      >
        <ChevronLeft size={16} />
        All Movies
      </Link>

      {/* ── Hero ──────────────────────────────────────────────────────── */}
      <div
        className="relative rounded-2xl overflow-hidden mb-10 p-6 sm:p-10"
        style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
      >
        {/* Blurred backdrop */}
        {movie.poster_url && (
          <div className="absolute inset-0 opacity-10">
            <Image src={movie.poster_url} alt="" fill className="object-cover blur-xl scale-110" />
          </div>
        )}

        <div className="relative z-10 flex flex-col sm:flex-row gap-8">
          {/* Poster */}
          <div
            className="relative w-44 h-64 rounded-xl overflow-hidden shrink-0 self-center sm:self-start"
            style={{ background: "var(--surface-2)", boxShadow: "0 20px 60px rgba(0,0,0,0.5)" }}
          >
            {movie.poster_url ? (
              <Image
                src={movie.poster_url}
                alt={movie.title}
                fill
                className="object-cover"
                sizes="176px"
                priority
              />
            ) : (
              <div className="flex items-center justify-center h-full text-5xl">🎬</div>
            )}
          </div>

          {/* Details */}
          <div className="flex flex-col justify-center">
            <h1 className="text-3xl sm:text-4xl font-bold mb-3 leading-tight" style={{ color: "var(--text)" }}>
              {movie.title}
            </h1>
            <div className="flex flex-wrap items-center gap-3 mb-5">
              <div className="flex items-center gap-1.5 text-sm font-bold" style={{ color: "var(--warning)" }}>
                <Star size={15} fill="currentColor" />
                {movie.rating.toFixed(1)} / 10
              </div>
              <span style={{ color: "var(--border-bright)" }}>·</span>
              <div className="flex items-center gap-1.5 text-sm" style={{ color: "var(--text-muted)" }}>
                <Clock size={13} />
                {movie.duration_min} min
              </div>
              <span style={{ color: "var(--border-bright)" }}>·</span>
              <div className="flex flex-wrap gap-1.5">
                {movie.genre.map((g) => (
                  <span
                    key={g}
                    className="text-xs px-2.5 py-1 rounded-full font-medium"
                    style={{ background: "var(--surface-3)", color: "var(--text-muted)", border: "1px solid var(--border)" }}
                  >
                    {g}
                  </span>
                ))}
              </div>
            </div>
            <p className="text-sm leading-relaxed max-w-2xl" style={{ color: "var(--text-muted)", lineHeight: "1.8" }}>
              {movie.description}
            </p>
          </div>
        </div>
      </div>

      {/* ── Showtimes ─────────────────────────────────────────────────── */}
      <h2 className="text-xl font-bold mb-4" style={{ color: "var(--text)" }}>
        Available Showtimes
      </h2>

      {movie.showtimes && movie.showtimes.length > 0 ? (
        <div className="grid gap-3">
          {movie.showtimes.map((st) => (
            <ShowtimeCard key={st.id} showtime={st} />
          ))}
        </div>
      ) : (
        <div
          className="text-center py-16 rounded-xl border"
          style={{ background: "var(--surface)", borderColor: "var(--border)", color: "var(--text-muted)" }}
        >
          No showtimes scheduled.
        </div>
      )}
    </div>
  );
}
