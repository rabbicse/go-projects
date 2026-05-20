"use client";

import Link from "next/link";
import { MapPin, Users, Ticket } from "lucide-react";
import type { Showtime } from "@/types";

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
}

function formatPrice(cents: number, currency: string) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency }).format(cents / 100);
}

export function ShowtimeCard({ showtime }: { showtime: Showtime }) {
  return (
    <Link href={`/showtimes/${showtime.id}`} className="group no-underline block">
      <div
        className="rounded-xl border p-5 transition-all duration-200"
        style={{
          background: "var(--surface)",
          borderColor: "var(--border)",
          transition: "border-color 0.2s, background 0.2s",
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLElement).style.borderColor = "var(--accent)";
          (e.currentTarget as HTMLElement).style.background = "var(--surface-2)";
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLElement).style.borderColor = "var(--border)";
          (e.currentTarget as HTMLElement).style.background = "var(--surface)";
        }}
      >
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-6">
            {/* Time */}
            <div>
              <div className="text-xl font-bold tabular-nums" style={{ color: "var(--text)" }}>
                {formatTime(showtime.start_time)}
                <span className="text-base font-normal mx-2" style={{ color: "var(--text-dim)" }}>→</span>
                {formatTime(showtime.end_time)}
              </div>
              <div className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>
                {formatDate(showtime.start_time)}
              </div>
            </div>

            {/* Meta */}
            <div className="hidden sm:flex items-center gap-4">
              <div className="flex items-center gap-1.5 text-sm" style={{ color: "var(--text-muted)" }}>
                <MapPin size={14} />
                {showtime.hall}
              </div>
              <div className="flex items-center gap-1.5 text-sm" style={{ color: "var(--text-muted)" }}>
                <Users size={14} />
                {showtime.total_seats} seats
              </div>
            </div>
          </div>

          {/* Price + CTA */}
          <div className="flex items-center gap-4 ml-auto">
            <div className="text-right">
              <div className="text-xl font-bold" style={{ color: "var(--accent)" }}>
                {formatPrice(showtime.price_cents, showtime.currency)}
              </div>
              <div className="text-xs" style={{ color: "var(--text-dim)" }}>per seat</div>
            </div>
            <div
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold"
              style={{ background: "var(--accent)", color: "#fff" }}
            >
              <Ticket size={15} />
              Book
            </div>
          </div>
        </div>
      </div>
    </Link>
  );
}
