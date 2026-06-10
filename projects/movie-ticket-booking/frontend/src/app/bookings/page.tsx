"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Ticket, ChevronLeft } from "lucide-react";
import { api, ApiError } from "@/lib/api";
import type { BookingResponse } from "@/types";

function getUserID(): string {
  if (typeof window === "undefined") return "";
  return sessionStorage.getItem("cinebook_user_id") ?? "";
}

const fmt = (cents: number, cur: string) =>
  new Intl.NumberFormat("en-US", { style: "currency", currency: cur }).format(cents / 100);

const fmtDate = (iso: string) =>
  new Date(iso).toLocaleDateString([], { weekday: "short", month: "short", day: "numeric", year: "numeric" });

const STATUS_STYLES: Record<string, { bg: string; color: string; border: string }> = {
  confirmed: { bg: "rgba(46,213,115,0.12)", color: "var(--success)", border: "var(--success)" },
  held:      { bg: "rgba(255,193,7,0.12)",  color: "var(--warning)", border: "var(--warning)" },
  released:  { bg: "var(--surface-2)",       color: "var(--text-muted)", border: "var(--border)" },
  expired:   { bg: "var(--surface-2)",       color: "var(--text-dim)",   border: "var(--border)" },
};

export default function BookingsPage() {
  const [bookings, setBookings] = useState<BookingResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [userID, setUserID] = useState("");

  useEffect(() => {
    const id = getUserID();
    setUserID(id);
    if (!id) { setLoading(false); return; }
    api.users.bookings(id)
      .then(setBookings)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load bookings"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <p style={{ textAlign: "center", padding: "6rem", color: "var(--text-muted)" }}>Loading…</p>;
  }

  return (
    <div className="page-container" style={{ paddingTop: "2.5rem", paddingBottom: "4rem" }}>
      <Link href="/" style={{
        display: "inline-flex", alignItems: "center", gap: "0.3rem",
        fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "2rem",
        transition: "color 0.15s",
      }}>
        <ChevronLeft size={14} /> All Movies
      </Link>

      <div style={{
        display: "flex", alignItems: "baseline", justifyContent: "space-between",
        flexWrap: "wrap", gap: "0.5rem", marginBottom: "1.5rem",
      }}>
        <h1 style={{ fontSize: "1.4rem", fontWeight: 700, color: "var(--text)" }}>My Bookings</h1>
        {userID && (
          <span style={{ fontSize: "0.68rem", color: "var(--text-dim)", fontFamily: "monospace" }}>
            {userID}
          </span>
        )}
      </div>

      {!userID ? (
        <div style={{
          textAlign: "center", padding: "4rem 1rem", borderRadius: "10px",
          background: "var(--surface)", border: "1px solid var(--border)",
          color: "var(--text-muted)", fontSize: "0.85rem",
        }}>
          No session found. Visit a showtime page to start a session.
        </div>
      ) : error ? (
        <div style={{
          textAlign: "center", padding: "3rem 1rem", borderRadius: "10px",
          background: "var(--surface)", border: "1px solid var(--danger)",
          color: "var(--danger)", fontSize: "0.85rem",
        }}>
          {error}
        </div>
      ) : bookings.length === 0 ? (
        <div style={{
          textAlign: "center", padding: "4rem 1rem", borderRadius: "10px",
          background: "var(--surface)", border: "1px solid var(--border)",
          color: "var(--text-muted)",
        }}>
          <Ticket size={40} style={{ margin: "0 auto 0.75rem", opacity: 0.3, display: "block" }} />
          <p style={{ fontSize: "0.85rem", marginBottom: "1rem" }}>No bookings yet.</p>
          <Link href="/" style={{ fontSize: "0.8rem", color: "var(--accent)" }}>
            Browse movies →
          </Link>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "0.625rem" }}>
          {bookings.map((b) => {
            const s = STATUS_STYLES[b.status] ?? STATUS_STYLES.released;
            return (
              <div key={b.id} style={{
                background: "var(--surface)", border: "1px solid var(--border)",
                borderRadius: "10px", padding: "1rem 1.25rem",
                display: "flex", alignItems: "center", justifyContent: "space-between",
                gap: "1rem", flexWrap: "wrap",
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.875rem" }}>
                  <div style={{
                    width: "36px", height: "36px", borderRadius: "8px", flexShrink: 0,
                    background: s.bg, border: `1px solid ${s.border}`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}>
                    <Ticket size={15} style={{ color: s.color }} />
                  </div>
                  <div>
                    <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "var(--text)", marginBottom: "0.2rem" }}>
                      #{b.id.slice(0, 8).toUpperCase()}
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                      {fmtDate(b.created_at)}
                      {b.seats.length > 0 && (
                        <> &bull; {b.seats.map((seat) => seat.id).join(", ")}</>
                      )}
                    </div>
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "1.25rem", flexWrap: "wrap" }}>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ fontSize: "1rem", fontWeight: 700, color: "var(--text)" }}>
                      {fmt(b.total_cents, b.currency)}
                    </div>
                    <div style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>
                      {b.seats.length} seat{b.seats.length !== 1 ? "s" : ""}
                    </div>
                  </div>
                  <span style={{
                    fontSize: "0.65rem", fontWeight: 700, letterSpacing: "0.06em",
                    padding: "0.25rem 0.65rem", borderRadius: "5px",
                    background: s.bg, color: s.color, border: `1px solid ${s.border}`,
                    textTransform: "uppercase",
                  }}>
                    {b.status}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
