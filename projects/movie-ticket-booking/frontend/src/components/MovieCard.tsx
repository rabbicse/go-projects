"use client";

import Image from "next/image";
import Link from "next/link";
import { Star, Ticket } from "lucide-react";
import type { Movie } from "@/types";

function fmtPrice(cents: number, currency: string) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency, minimumFractionDigits: 0 }).format(cents / 100);
}

function minPrice(movie: Movie): { cents: number; currency: string } | null {
  if (!movie.showtimes?.length) return null;
  const min = movie.showtimes.reduce((a, b) => (a.price_cents < b.price_cents ? a : b));
  return { cents: min.price_cents, currency: min.currency };
}

export function MovieCard({ movie }: { movie: Movie }) {
  const price = minPrice(movie);

  return (
    <Link href={`/movies/${movie.id}`} style={{ display: "block", textDecoration: "none" }}>
      <article
        style={{
          background: "var(--surface)",
          border: "1px solid var(--border)",
          borderRadius: "10px",
          overflow: "hidden",
          transition: "border-color 0.2s, transform 0.2s, box-shadow 0.2s",
          cursor: "pointer",
        }}
        onMouseEnter={(e) => {
          const el = e.currentTarget as HTMLElement;
          el.style.borderColor = "var(--accent)";
          el.style.transform = "translateY(-3px)";
          el.style.boxShadow = "0 8px 30px rgba(79,195,247,0.12)";
        }}
        onMouseLeave={(e) => {
          const el = e.currentTarget as HTMLElement;
          el.style.borderColor = "var(--border)";
          el.style.transform = "translateY(0)";
          el.style.boxShadow = "none";
        }}
      >
        {/* ── Poster — 2:3 aspect ratio ─────────────────────── */}
        <div style={{ position: "relative", aspectRatio: "2 / 3", background: "var(--surface-2)", overflow: "hidden" }}>
          {movie.poster_url ? (
            <Image
              src={movie.poster_url}
              alt={movie.title}
              fill
              sizes="(max-width: 640px) 50vw, (max-width: 1024px) 33vw, 25vw"
              style={{ objectFit: "cover", transition: "transform 0.4s" }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLImageElement).style.transform = "scale(1.04)"; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLImageElement).style.transform = "scale(1)"; }}
            />
          ) : (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", fontSize: "2.5rem" }}>
              🎬
            </div>
          )}

          {/* Gradient overlay */}
          <div style={{ position: "absolute", inset: 0, background: "linear-gradient(to top, rgba(0,0,0,0.7) 0%, transparent 55%)" }} />

          {/* Rating badge */}
          <div style={{
            position: "absolute", top: "0.5rem", right: "0.5rem",
            display: "flex", alignItems: "center", gap: "0.25rem",
            background: "rgba(0,0,0,0.8)", color: "var(--warning)",
            fontSize: "0.65rem", fontWeight: 700,
            padding: "0.25rem 0.5rem", borderRadius: "5px",
            backdropFilter: "blur(4px)",
          }}>
            <Star size={10} fill="currentColor" /> {movie.rating.toFixed(1)}
          </div>

          {/* Showtimes pill */}
          {(movie.showtimes?.length ?? 0) > 0 && (
            <div style={{
              position: "absolute", bottom: "0.5rem", left: "0.5rem",
              display: "flex", alignItems: "center", gap: "0.25rem",
              background: "rgba(0,0,0,0.75)", color: "rgba(255,255,255,0.75)",
              fontSize: "0.62rem", padding: "0.2rem 0.5rem", borderRadius: "5px",
            }}>
              <Ticket size={9} /> {movie.showtimes.length} show{movie.showtimes.length !== 1 ? "s" : ""}
            </div>
          )}
        </div>

        {/* ── Info ─────────────────────────────────────────── */}
        <div style={{ padding: "0.75rem 0.875rem" }}>
          <p style={{
            fontWeight: 600, fontSize: "0.82rem", color: "var(--text)",
            lineHeight: 1.3, marginBottom: "0.4rem",
            display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical", overflow: "hidden",
          }}>
            {movie.title}
          </p>

          {/* Genre tags */}
          <div style={{ display: "flex", gap: "0.3rem", flexWrap: "wrap", marginBottom: "0.5rem" }}>
            {movie.genre.slice(0, 2).map((g) => (
              <span key={g} style={{
                fontSize: "0.6rem", padding: "0.15rem 0.45rem", borderRadius: "4px",
                background: "var(--surface-3)", color: "var(--text-muted)",
              }}>
                {g}
              </span>
            ))}
          </div>

          {/* Price */}
          {price && price.cents > 0 && (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span style={{ fontSize: "0.65rem", color: "var(--text-dim)" }}>from</span>
              <span style={{ fontSize: "0.82rem", fontWeight: 700, color: "var(--accent)" }}>
                {fmtPrice(price.cents, price.currency)}
              </span>
            </div>
          )}
        </div>
      </article>
    </Link>
  );
}
