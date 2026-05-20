import Image from "next/image";
import Link from "next/link";
import { Star, Clock, Ticket } from "lucide-react";
import { api } from "@/lib/api";
import { FALLBACK_MOVIES } from "@/lib/fallback-data";
import { MovieCard } from "@/components/MovieCard";
import type { Movie } from "@/types";

export const revalidate = 60;

function fmtPrice(cents: number, currency: string) {
  return new Intl.NumberFormat("en-US", {
    style: "currency", currency, minimumFractionDigits: 0,
  }).format(cents / 100);
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

  return (
    <>
      {/* ── Fallback banner ─────────────────────────────────────────── */}
      {usingFallback && (
        <div style={{
          background: "var(--surface-2)",
          borderBottom: "1px solid var(--border)",
          padding: "0.6rem var(--page-px)",
          fontSize: "0.72rem",
          color: "var(--text-muted)",
          display: "flex",
          alignItems: "center",
          gap: "0.5rem",
        }}>
          <span style={{ color: "var(--warning)" }}>●</span>
          Demo data — backend offline.
          Start <code style={{ background: "var(--surface-3)", padding: "0 0.3rem", borderRadius: "3px" }}>localhost:8080</code> to see live showtimes.
        </div>
      )}

      {/* ── Hero — full-bleed ──────────────────────────────────────── */}
      {featured && (
        <section style={{ position: "relative", width: "100%", minHeight: "500px", overflow: "hidden" }}>
          {/* Backdrop */}
          {featured.poster_url && (
            <>
              <Image
                src={featured.poster_url}
                alt=""
                fill
                priority
                sizes="100vw"
                style={{ objectFit: "cover", objectPosition: "center 20%", filter: "brightness(0.45)" }}
              />
              {/* Left-to-right fade so text is readable */}
              <div style={{
                position: "absolute", inset: 0,
                background: "linear-gradient(to right, rgba(15,15,15,0.98) 0%, rgba(15,15,15,0.82) 45%, rgba(15,15,15,0.3) 100%)",
              }} />
              {/* Bottom fade into page bg */}
              <div style={{
                position: "absolute", bottom: 0, left: 0, right: 0, height: "120px",
                background: "linear-gradient(to bottom, transparent, var(--bg))",
              }} />
            </>
          )}

          {/* Content — centred via page-container */}
          <div className="page-container" style={{
            position: "relative", zIndex: 1,
            display: "flex", alignItems: "flex-end",
            minHeight: "500px", paddingBottom: "3.5rem", paddingTop: "3.5rem",
          }}>
            <div style={{ maxWidth: "540px" }}>
              {/* Badge */}
              <div style={{
                display: "inline-flex", alignItems: "center", gap: "0.4rem",
                background: "var(--accent)", color: "#000",
                fontSize: "0.65rem", fontWeight: 700, letterSpacing: "0.08em",
                padding: "0.3rem 0.75rem", borderRadius: "999px", marginBottom: "1rem",
              }}>
                <Ticket size={11} /> FEATURED NOW
              </div>

              {/* Title */}
              <h1 style={{
                fontSize: "clamp(2rem, 5vw, 3.25rem)",
                fontWeight: 700, lineHeight: 1.1,
                color: "#fff", marginBottom: "1rem",
                letterSpacing: "-0.02em",
              }}>
                {featured.title}
              </h1>

              {/* Meta row */}
              <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "0.75rem", marginBottom: "0.875rem" }}>
                <span style={{ display: "flex", alignItems: "center", gap: "0.3rem", color: "var(--warning)", fontWeight: 700, fontSize: "0.85rem" }}>
                  <Star size={14} fill="currentColor" /> {featured.rating.toFixed(1)}
                </span>
                <span style={{ color: "rgba(255,255,255,0.4)", fontSize: "0.75rem" }}>•</span>
                <span style={{ display: "flex", alignItems: "center", gap: "0.3rem", color: "rgba(255,255,255,0.6)", fontSize: "0.8rem" }}>
                  <Clock size={12} /> {featured.duration_min} min
                </span>
                {featured.genre.slice(0, 3).map((g) => (
                  <span key={g} style={{
                    fontSize: "0.72rem", padding: "0.2rem 0.6rem", borderRadius: "4px",
                    background: "rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.65)",
                    border: "1px solid rgba(255,255,255,0.12)",
                  }}>
                    {g}
                  </span>
                ))}
              </div>

              {/* Description */}
              <p style={{
                fontSize: "0.82rem", lineHeight: 1.75,
                color: "rgba(255,255,255,0.58)", marginBottom: "1.75rem",
                display: "-webkit-box", WebkitLineClamp: 3, WebkitBoxOrient: "vertical", overflow: "hidden",
              }}>
                {featured.description}
              </p>

              {/* CTAs */}
              <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                {featured.showtimes?.slice(0, 1).map((st) => (
                  <Link key={st.id} href={`/showtimes/${st.id}`} style={{
                    display: "inline-flex", alignItems: "center", gap: "0.5rem",
                    background: "var(--accent)", color: "#000",
                    fontSize: "0.8rem", fontWeight: 700,
                    padding: "0.65rem 1.4rem", borderRadius: "8px",
                    transition: "opacity 0.15s",
                  }}
                  onMouseEnter={undefined} // server component — hover handled by CSS only
                  >
                    <Ticket size={15} />
                    Book Now
                    {st.price_cents > 0 && (
                      <span style={{ opacity: 0.7 }}>· {fmtPrice(st.price_cents, st.currency)}</span>
                    )}
                  </Link>
                ))}
                <Link href={`/movies/${featured.id}`} style={{
                  display: "inline-flex", alignItems: "center",
                  background: "rgba(255,255,255,0.08)", color: "rgba(255,255,255,0.85)",
                  border: "1px solid rgba(255,255,255,0.18)",
                  fontSize: "0.8rem", fontWeight: 600,
                  padding: "0.65rem 1.4rem", borderRadius: "8px",
                }}>
                  All Showtimes →
                </Link>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* ── Now Playing ────────────────────────────────────────────── */}
      <div className="page-container" style={{ paddingTop: "3rem", paddingBottom: "4rem" }}>
        <p className="section-label">Now Playing</p>
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
          gap: "1.25rem",
        }}>
          {movies.map((movie) => (
            <MovieCard key={movie.id} movie={movie} />
          ))}
        </div>
      </div>
    </>
  );
}
