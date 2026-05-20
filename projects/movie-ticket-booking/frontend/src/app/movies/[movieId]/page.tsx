import Image from "next/image";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Star, Clock, ChevronLeft } from "lucide-react";
import { api } from "@/lib/api";
import { FALLBACK_MOVIES } from "@/lib/fallback-data";
import { ShowtimeCard } from "@/components/ShowtimeCard";
import type { Movie } from "@/types";

export const revalidate = 30;

interface Props { params: Promise<{ movieId: string }> }

export default async function MoviePage({ params }: Props) {
  const { movieId } = await params;
  let movie: Movie | undefined;
  try { movie = await api.movies.get(movieId); }
  catch { movie = FALLBACK_MOVIES.find((m) => m.id === movieId); }
  if (!movie) notFound();

  return (
    <div className="page-container" style={{ paddingTop: "2.5rem", paddingBottom: "4rem" }}>
      {/* Back */}
      <Link href="/" style={{
        display: "inline-flex", alignItems: "center", gap: "0.3rem",
        fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "2rem",
        transition: "color 0.15s",
      }}>
        <ChevronLeft size={14} /> All Movies
      </Link>

      {/* ── Hero card ──────────────────────────────────────────────── */}
      <div style={{
        position: "relative", borderRadius: "12px", overflow: "hidden",
        background: "var(--surface)", border: "1px solid var(--border)",
        marginBottom: "2.5rem",
      }}>
        {/* blurred backdrop */}
        {movie.poster_url && (
          <div style={{ position: "absolute", inset: 0, opacity: 0.08 }}>
            <Image src={movie.poster_url} alt="" fill style={{ objectFit: "cover", filter: "blur(24px)", transform: "scale(1.1)" }} />
          </div>
        )}

        <div style={{
          position: "relative", zIndex: 1,
          display: "flex", flexDirection: "row", gap: "2rem", padding: "2rem",
          flexWrap: "wrap",
        }}>
          {/* Poster */}
          <div style={{
            position: "relative", width: "150px", aspectRatio: "2/3",
            borderRadius: "8px", overflow: "hidden", flexShrink: 0,
            background: "var(--surface-2)", boxShadow: "0 16px 48px rgba(0,0,0,0.5)",
            alignSelf: "flex-start",
          }}>
            {movie.poster_url
              ? <Image src={movie.poster_url} alt={movie.title} fill sizes="150px" style={{ objectFit: "cover" }} priority />
              : <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", fontSize: "3rem" }}>🎬</div>}
          </div>

          {/* Details */}
          <div style={{ flex: 1, minWidth: "240px", display: "flex", flexDirection: "column", justifyContent: "center" }}>
            <h1 style={{
              fontSize: "clamp(1.5rem, 3vw, 2.25rem)", fontWeight: 700,
              color: "var(--text)", marginBottom: "0.75rem", lineHeight: 1.15, letterSpacing: "-0.02em",
            }}>
              {movie.title}
            </h1>

            {/* Meta */}
            <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "0.6rem", marginBottom: "1rem" }}>
              <span style={{ display: "flex", alignItems: "center", gap: "0.3rem", color: "var(--warning)", fontWeight: 700, fontSize: "0.85rem" }}>
                <Star size={13} fill="currentColor" /> {movie.rating.toFixed(1)}
              </span>
              <span style={{ color: "var(--border-bright)" }}>·</span>
              <span style={{ display: "flex", alignItems: "center", gap: "0.3rem", color: "var(--text-muted)", fontSize: "0.8rem" }}>
                <Clock size={12} /> {movie.duration_min} min
              </span>
              <span style={{ color: "var(--border-bright)" }}>·</span>
              <div style={{ display: "flex", gap: "0.35rem", flexWrap: "wrap" }}>
                {movie.genre.map((g) => (
                  <span key={g} style={{
                    fontSize: "0.68rem", padding: "0.2rem 0.6rem", borderRadius: "5px",
                    background: "var(--surface-3)", color: "var(--text-muted)", border: "1px solid var(--border)",
                  }}>{g}</span>
                ))}
              </div>
            </div>

            <p style={{ fontSize: "0.82rem", lineHeight: 1.75, color: "var(--text-muted)", maxWidth: "560px" }}>
              {movie.description}
            </p>
          </div>
        </div>
      </div>

      {/* ── Showtimes ──────────────────────────────────────────────── */}
      <p className="section-label">Available Showtimes</p>

      {movie.showtimes && movie.showtimes.length > 0 ? (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.625rem" }}>
          {movie.showtimes.map((st) => <ShowtimeCard key={st.id} showtime={st} />)}
        </div>
      ) : (
        <div style={{
          textAlign: "center", padding: "4rem 1rem", borderRadius: "10px",
          background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text-muted)",
          fontSize: "0.85rem",
        }}>
          No showtimes scheduled.
        </div>
      )}
    </div>
  );
}
