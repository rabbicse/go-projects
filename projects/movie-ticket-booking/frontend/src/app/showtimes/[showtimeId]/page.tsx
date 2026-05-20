"use client";

import { use, useCallback, useEffect, useRef, useState } from "react";
import { ChevronRight, AlertCircle } from "lucide-react";
import { api } from "@/lib/api";
import { SeatGrid } from "@/components/SeatGrid";
import { Checkout } from "@/components/Checkout";
import type { ActiveSession, BookingResponse, Showtime } from "@/types";

const MAX_SEATS = parseInt(process.env.NEXT_PUBLIC_MAX_SEATS ?? "4", 10);

function getUserID(): string {
  if (typeof window === "undefined") return "";
  const stored = sessionStorage.getItem("cinebook_user_id");
  if (stored) return stored;
  const id = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
  sessionStorage.setItem("cinebook_user_id", id);
  return id;
}

function formatTime(iso: string) {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString([], { weekday: "long", month: "long", day: "numeric" });
}
function formatPrice(cents: number, currency: string) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency }).format(cents / 100);
}

interface Props {
  params: Promise<{ showtimeId: string }>;
}

export default function ShowtimePage({ params }: Props) {
  const { showtimeId } = use(params);
  const [userID] = useState(getUserID);
  const [showtime, setShowtime] = useState<Showtime | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedSeats, setSelectedSeats] = useState<string[]>([]);
  const [activeSession, setActiveSession] = useState<ActiveSession | null>(null);
  const [holdError, setHoldError] = useState<string | null>(null);
  const [holding, setHolding] = useState(false);
  const [confirmedBooking, setConfirmedBooking] = useState<BookingResponse | null>(null);

  const sessionRef = useRef(activeSession);
  sessionRef.current = activeSession;

  useEffect(() => {
    api.showtimes
      .get(showtimeId)
      .then(setShowtime)
      .catch(() => setError("Showtime not found"))
      .finally(() => setLoading(false));
  }, [showtimeId]);

  // Release session on page unload
  useEffect(() => {
    const handler = () => {
      const s = sessionRef.current;
      if (s) {
        navigator.sendBeacon(
          `/api/v1/sessions/${s.sessionID}`,
          JSON.stringify({ user_id: userID })
        );
      }
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [userID]);

  const toggleSeat = useCallback(
    (seatID: string) => {
      if (activeSession) return;
      setSelectedSeats((prev) =>
        prev.includes(seatID)
          ? prev.filter((s) => s !== seatID)
          : prev.length < MAX_SEATS
          ? [...prev, seatID]
          : prev
      );
    },
    [activeSession]
  );

  async function holdSeats() {
    if (selectedSeats.length === 0) return;
    setHolding(true);
    setHoldError(null);
    try {
      const res = await api.showtimes.hold(showtimeId, userID, selectedSeats);
      setActiveSession({
        sessionID: res.session_id,
        showtimeID: res.showtime_id,
        movieID: res.movie_id,
        seatIDs: res.seat_ids,
        expiresAt: res.expires_at,
      });
      setSelectedSeats([]);
    } catch (e) {
      setHoldError(e instanceof Error ? e.message : "Failed to hold seats");
    } finally {
      setHolding(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-32" style={{ color: "var(--text-muted)" }}>
        Loading showtime…
      </div>
    );
  }
  if (error || !showtime) {
    return (
      <div className="text-center py-20" style={{ color: "var(--confirmed)" }}>
        <AlertCircle size={40} className="mx-auto mb-3" />
        <p>{error ?? "Showtime not found"}</p>
      </div>
    );
  }

  return (
    <div>
      {/* Breadcrumb */}
      <nav className="flex items-center gap-1 text-sm mb-6" style={{ color: "var(--text-muted)" }}>
        <a href="/" style={{ color: "var(--accent)" }}>
          Movies
        </a>
        <ChevronRight size={14} />
        <a href={`/movies/${showtime.movie_id}`} style={{ color: "var(--accent)" }}>
          Movie
        </a>
        <ChevronRight size={14} />
        <span>
          {formatDate(showtime.start_time)} {formatTime(showtime.start_time)}
        </span>
      </nav>

      {/* Header */}
      <div className="mb-8 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold mb-1" style={{ color: "var(--text)" }}>
            {showtime.hall}
          </h1>
          <p style={{ color: "var(--text-muted)" }}>
            {formatDate(showtime.start_time)} &bull; {formatTime(showtime.start_time)} → {formatTime(showtime.end_time)}
          </p>
        </div>
        <div
          className="text-right rounded-xl px-4 py-2"
          style={{ background: "var(--surface)", border: "1px solid var(--border)" }}
        >
          <div className="text-2xl font-bold" style={{ color: "var(--accent)" }}>
            {formatPrice(showtime.price_cents, showtime.currency)}
          </div>
          <div className="text-xs" style={{ color: "var(--text-muted)" }}>
            per seat · max {MAX_SEATS} seats
          </div>
        </div>
      </div>

      <div className="flex flex-col lg:flex-row gap-8 items-start">
        {/* Seat Grid */}
        <div
          className="flex-1 rounded-xl border p-6"
          style={{ background: "var(--surface)", borderColor: "var(--border)" }}
        >
          <SeatGrid
            showtimeId={showtimeId}
            rows={showtime.rows}
            seatsPerRow={showtime.seats_per_row}
            userID={userID}
            selectedSeats={selectedSeats}
            maxSeats={MAX_SEATS}
            onToggleSeat={toggleSeat}
            activeSessionSeats={activeSession?.seatIDs ?? []}
          />

          {/* Hold button (when seats selected and no active session) */}
          {!activeSession && selectedSeats.length > 0 && (
            <div className="mt-6 flex flex-col items-center gap-2">
              <button
                onClick={holdSeats}
                disabled={holding}
                className="w-full max-w-xs py-3 rounded-xl font-bold text-sm transition-opacity disabled:opacity-60"
                style={{ background: "var(--accent)", color: "#fff" }}
              >
                {holding ? "Holding…" : `Hold ${selectedSeats.length} seat${selectedSeats.length > 1 ? "s" : ""}`}
              </button>
              {holdError && (
                <p className="text-xs text-center" style={{ color: "var(--confirmed)" }}>
                  {holdError}
                </p>
              )}
            </div>
          )}
        </div>

        {/* Checkout sidebar */}
        <div className="w-full lg:w-80 shrink-0">
          {confirmedBooking ? (
            <div
              className="rounded-xl border p-6 text-center space-y-2"
              style={{ background: "var(--surface)", borderColor: "#22c55e33" }}
            >
              <div className="text-3xl">🎟</div>
              <h3 className="font-bold" style={{ color: "var(--success)" }}>
                Enjoy the show!
              </h3>
              <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                Confirmation #{confirmedBooking.id.slice(0, 8).toUpperCase()}
              </p>
            </div>
          ) : activeSession ? (
            <Checkout
              session={activeSession}
              userID={userID}
              priceCents={showtime.price_cents}
              currency={showtime.currency}
              maxSeats={MAX_SEATS}
              onConfirmed={(b) => {
                setConfirmedBooking(b);
                setActiveSession(null);
              }}
              onReleased={() => setActiveSession(null)}
            />
          ) : (
            <div
              className="rounded-xl border p-6 text-center"
              style={{ background: "var(--surface)", borderColor: "var(--border)" }}
            >
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>
                Select up to <strong>{MAX_SEATS}</strong> seats from the grid, then hold them.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
