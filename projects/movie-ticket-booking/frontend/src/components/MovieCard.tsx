"use client";

import Image from "next/image";
import Link from "next/link";
import { Star, Clock, Ticket } from "lucide-react";
import type { Movie } from "@/types";

function formatPrice(cents: number, currency: string) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency, minimumFractionDigits: 0 }).format(cents / 100);
}

function minPrice(movie: Movie): number {
  if (!movie.showtimes?.length) return 0;
  return Math.min(...movie.showtimes.map((s) => s.price_cents));
}

export function MovieCard({ movie }: { movie: Movie }) {
  const price = minPrice(movie);
  return (
    <Link href={`/movies/${movie.id}`} className="group block no-underline">
      <article
        className="rounded-xl overflow-hidden border transition-all duration-300 group-hover:-translate-y-1"
        style={{
          background: "var(--surface)",
          borderColor: "var(--border)",
          boxShadow: "0 0 0 0 transparent",
          transition: "transform 0.2s, border-color 0.2s, box-shadow 0.2s",
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLElement).style.borderColor = "var(--accent)";
          (e.currentTarget as HTMLElement).style.boxShadow = "0 0 24px -4px var(--accent-glow)";
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLElement).style.borderColor = "var(--border)";
          (e.currentTarget as HTMLElement).style.boxShadow = "none";
        }}
      >
        {/* Poster */}
        <div className="relative h-64 overflow-hidden" style={{ background: "var(--surface-2)" }}>
          {movie.poster_url ? (
            <Image
              src={movie.poster_url}
              alt={movie.title}
              fill
              className="object-cover transition-transform duration-500 group-hover:scale-105"
              sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, 25vw"
            />
          ) : (
            <div className="flex items-center justify-center h-full text-4xl">🎬</div>
          )}
          <div className="absolute inset-0 bg-gradient-to-t from-black/50 via-transparent to-transparent" />
          {/* Rating badge */}
          <div
            className="absolute top-2.5 right-2.5 flex items-center gap-1 px-2 py-1 rounded-full text-xs font-semibold"
            style={{ background: "rgba(0,0,0,0.75)", color: "var(--warning)" }}
          >
            <Star size={11} fill="currentColor" />
            {movie.rating.toFixed(1)}
          </div>
          {/* Showtimes count badge */}
          {(movie.showtimes?.length ?? 0) > 0 && (
            <div
              className="absolute bottom-2.5 left-2.5 flex items-center gap-1 px-2 py-1 rounded-full text-xs"
              style={{ background: "rgba(0,0,0,0.75)", color: "rgba(255,255,255,0.8)" }}
            >
              <Ticket size={10} />
              {movie.showtimes.length} {movie.showtimes.length === 1 ? "showtime" : "showtimes"}
            </div>
          )}
        </div>

        {/* Info */}
        <div className="p-4">
          <h3 className="font-semibold text-sm mb-1.5 leading-snug" style={{ color: "var(--text)" }}>
            {movie.title}
          </h3>
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <div className="flex items-center gap-1 text-xs" style={{ color: "var(--text-muted)" }}>
              <Clock size={11} />
              {movie.duration_min}m
            </div>
            {movie.genre.slice(0, 2).map((g) => (
              <span
                key={g}
                className="text-xs px-1.5 py-0.5 rounded"
                style={{ background: "var(--surface-3)", color: "var(--text-muted)" }}
              >
                {g}
              </span>
            ))}
          </div>
          {price > 0 && (
            <div className="flex items-center justify-between mt-2">
              <span className="text-xs" style={{ color: "var(--text-dim)" }}>from</span>
              <span className="text-sm font-bold" style={{ color: "var(--accent)" }}>
                {formatPrice(price, "USD")}
              </span>
            </div>
          )}
        </div>
      </article>
    </Link>
  );
}
