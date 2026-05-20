"use client";

import { use, useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { SeatGrid, type SeatState } from "@/components/SeatGrid";
import type { ActiveSession, BookingResponse, Showtime } from "@/types";

const MAX_SEATS      = parseInt(process.env.NEXT_PUBLIC_MAX_SEATS ?? "4", 10);
const PAYMENT_TTL_S  = 180; // 3-minute payment window

function getUserID(): string {
  if (typeof window === "undefined") return "";
  const k = "cinebook_user_id";
  const v = sessionStorage.getItem(k);
  if (v) return v;
  const id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  sessionStorage.setItem(k, id);
  return id;
}

const fmt = (cents: number, cur: string) =>
  new Intl.NumberFormat("en-US", { style: "currency", currency: cur }).format(cents / 100);
const fmtTime = (iso: string) =>
  new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const fmtDate = (iso: string) =>
  new Date(iso).toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" });
function countdown(unix: number): string {
  const s = Math.max(0, unix - Math.floor(Date.now() / 1000));
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

type Stage = "browse" | "checkout" | "paying" | "confirmed";

export default function ShowtimePage({ params }: { params: Promise<{ showtimeId: string }> }) {
  const { showtimeId } = use(params);
  const [userID]   = useState(getUserID);
  const [showtime, setShowtime] = useState<Showtime | null>(null);
  const [loading,  setLoading]  = useState(true);
  const [fetchErr, setFetchErr] = useState<string | null>(null);

  // ── booking state ──────────────────────────────────────────────
  const [stage,     setStage]     = useState<Stage>("browse");
  const [selected,  setSelected]  = useState<string[]>([]);   // optimistic local seats
  const [session,   setSession]   = useState<ActiveSession | null>(null);
  const [payExpiry, setPayExpiry] = useState<number | null>(null);
  const [confirmed, setConfirmed] = useState<BookingResponse | null>(null);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [busy,      setBusy]      = useState(false);
  const [tick,      setTick]      = useState(0); // 1-second heartbeat

  const sessionRef = useRef(session);
  sessionRef.current = session;

  // ── data fetch ─────────────────────────────────────────────────
  useEffect(() => {
    api.showtimes.get(showtimeId)
      .then(setShowtime)
      .catch(() => setFetchErr("Showtime not found"))
      .finally(() => setLoading(false));
  }, [showtimeId]);

  // ── 1-second heartbeat for countdowns ─────────────────────────
  useEffect(() => {
    const id = setInterval(() => setTick(t => t + 1), 1000);
    return () => clearInterval(id);
  }, []);

  // ── auto-release when hold timer expires ───────────────────────
  useEffect(() => {
    if (!session) return;
    if (session.expiresAt - Math.floor(Date.now() / 1000) <= 0) doRelease();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  // ── auto-release when payment timer expires ────────────────────
  useEffect(() => {
    if (stage !== "paying" || !payExpiry) return;
    if (payExpiry - Math.floor(Date.now() / 1000) <= 0) doRelease();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  // ── release on page unload ─────────────────────────────────────
  useEffect(() => {
    const h = () => {
      const s = sessionRef.current;
      if (s) navigator.sendBeacon(`/api/v1/sessions/${s.sessionID}`, JSON.stringify({ user_id: userID }));
    };
    window.addEventListener("beforeunload", h);
    return () => window.removeEventListener("beforeunload", h);
  }, [userID]);

  // ── helpers ────────────────────────────────────────────────────
  function errFor(ms = 3000) {
    return (e: unknown) => {
      setActionErr(e instanceof Error ? e.message : "Error");
      setTimeout(() => setActionErr(null), ms);
    };
  }

  // ── actions ────────────────────────────────────────────────────

  /**
   * Re-hold: release existing session (if any) then hold the new seat list.
   * Called on every seat click so the user can build up to MAX_SEATS seats
   * without ever pressing a "Hold" button.
   */
  const reHold = useCallback(async (newSeats: string[]) => {
    setBusy(true);
    setActionErr(null);

    // Optimistic UI — seats turn gold immediately
    setSelected(newSeats);

    const prev = sessionRef.current;
    try {
      // Release previous session if any (best-effort)
      if (prev) {
        try { await api.sessions.release(prev.sessionID, userID); } catch { /* expired already */ }
        setSession(null);
      }

      if (newSeats.length === 0) {
        setStage("browse");
        return;
      }

      const res = await api.showtimes.hold(showtimeId, userID, newSeats);
      setSession({
        sessionID:  res.session_id,
        showtimeID: res.showtime_id,
        movieID:    res.movie_id,
        seatIDs:    res.seat_ids,
        expiresAt:  res.expires_at,
      });
      setStage("checkout");
    } catch (e) {
      // Revert optimistic selection on error
      setSelected(prev?.seatIDs ?? []);
      setStage(prev ? "checkout" : "browse");
      errFor()(e);
    } finally {
      setBusy(false);
    }
  }, [showtimeId, userID]);

  const doRelease = useCallback(async () => {
    const s = sessionRef.current;
    setBusy(true);
    if (s) {
      try { await api.sessions.release(s.sessionID, userID); } catch { /* ignore */ }
    }
    setSession(null);
    setSelected([]);
    setStage("browse");
    setPayExpiry(null);
    setActionErr(null);
    setBusy(false);
  }, [userID]);

  async function doConfirm() {
    const s = sessionRef.current;
    if (!s || busy) return;
    setBusy(true);
    setActionErr(null);
    try {
      const booking = await api.sessions.confirm(s.sessionID, userID);
      setConfirmed(booking);
      setSession(null);
      setSelected([]);
      setStage("confirmed");
      setPayExpiry(null);
    } catch (e) {
      errFor()(e);
    } finally {
      setBusy(false);
    }
  }

  // ── seat click handler ─────────────────────────────────────────
  function handleSeatClick(seatID: string, state: SeatState) {
    if (busy || stage === "paying" || stage === "confirmed") return;

    if (state === "available") {
      if (selected.length >= MAX_SEATS) return; // at limit — ignore
      reHold([...selected, seatID]);
    } else if (state === "held-mine") {
      const next = selected.filter(s => s !== seatID);
      reHold(next); // re-hold remaining, or release if empty
    }
  }

  // ── render ────────────────────────────────────────────────────
  if (loading)  return <p style={{ textAlign: "center", padding: "6rem", color: "var(--text-muted)" }}>Loading…</p>;
  if (fetchErr || !showtime) return <p style={{ textAlign: "center", padding: "6rem", color: "var(--danger)" }}>{fetchErr ?? "Not found"}</p>;

  const holdLeft = session ? Math.max(0, session.expiresAt - Math.floor(Date.now() / 1000)) : 0;
  const payLeft  = payExpiry ? Math.max(0, payExpiry - Math.floor(Date.now() / 1000)) : 0;

  return (
    <div className="page-container" style={{ paddingTop: "2.5rem", paddingBottom: "4rem" }}>

      {/* Showtime header */}
      <div style={{
        display: "flex", alignItems: "baseline", justifyContent: "space-between",
        flexWrap: "wrap", gap: "1rem",
        marginBottom: "1.5rem", paddingBottom: "1rem", borderBottom: "1px solid var(--border)",
      }}>
        <div>
          <h2 style={{ fontSize: "1.1rem", fontWeight: 600, color: "var(--text)", marginBottom: "0.2rem" }}>
            {showtime.hall}
          </h2>
          <p style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
            {fmtDate(showtime.start_time)} &bull; {fmtTime(showtime.start_time)} &rarr; {fmtTime(showtime.end_time)}
            &nbsp;&bull;&nbsp;{showtime.rows * showtime.seats_per_row} seats total &bull; max {MAX_SEATS} per booking
          </p>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: "1.3rem", fontWeight: 700, color: "var(--accent)" }}>
            {fmt(showtime.price_cents, showtime.currency)}
          </div>
          <div style={{ fontSize: "0.68rem", color: "var(--text-muted)" }}>per seat</div>
        </div>
      </div>

      {/* Error bar */}
      {actionErr && (
        <div style={{
          marginBottom: "1rem", padding: "0.5rem 0.875rem", borderRadius: "6px",
          background: "rgba(231,76,60,0.1)", border: "1px solid var(--danger)",
          fontSize: "0.78rem", color: "var(--danger)",
        }}>
          {actionErr}
        </div>
      )}

      {/* Main: grid + panel */}
      <div style={{ display: "flex", gap: "2rem", alignItems: "flex-start", flexWrap: "wrap" }}>

        {/* Seat grid */}
        <div style={{ flex: 1, minWidth: "280px" }}>
          <SeatGrid
            showtimeId={showtimeId}
            rows={showtime.rows}
            seatsPerRow={showtime.seats_per_row}
            userID={userID}
            selectedSeats={selected}
            onClickSeat={handleSeatClick}
            interactive={stage === "browse" || stage === "checkout"}
          />
        </div>

        {/* Side panel */}
        <div style={{ width: "256px", flexShrink: 0 }}>

          {/* BROWSE — nothing selected */}
          {stage === "browse" && selected.length === 0 && (
            <Panel>
              <PanelTitle>Checkout</PanelTitle>
              <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", lineHeight: 1.65 }}>
                Click any available seat to hold it.<br />
                Click it again to release.<br />
                Up to {MAX_SEATS} seats per booking.
              </p>
            </Panel>
          )}

          {/* CHECKOUT — seats held */}
          {stage === "checkout" && session && (
            <Panel>
              <PanelTitle>Checkout</PanelTitle>

              {/* Selected seats chips */}
              <div style={{ display: "flex", gap: "0.35rem", flexWrap: "wrap", marginBottom: "0.875rem" }}>
                {session.seatIDs.map(id => (
                  <span key={id} style={{
                    fontSize: "0.72rem", fontWeight: 600,
                    background: "var(--held-mine)", color: "#000",
                    padding: "0.2rem 0.55rem", borderRadius: "4px",
                  }}>{id}</span>
                ))}
              </div>

              <InfoRow label="Price" value={fmt(showtime.price_cents * session.seatIDs.length, showtime.currency)} bold />
              <InfoRow label="Session" value={session.sessionID.slice(0, 8) + "…"} />

              <div style={{ margin: "0.875rem 0", textAlign: "center" }}>
                <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: "0.2rem" }}>
                  Hold expires in
                </div>
                <Countdown value={countdown(session.expiresAt)} urgent={holdLeft < 60} />
              </div>

              <p style={{ fontSize: "0.68rem", color: "var(--text-dim)", marginBottom: "0.875rem", textAlign: "center" }}>
                Click a gold seat to remove it &bull; click available seat to add
              </p>

              <Btn accent onClick={proceedToPayment} disabled={busy}>
                Proceed to Payment →
              </Btn>
              <Btn danger onClick={doRelease} disabled={busy} style={{ marginTop: "0.45rem" }}>
                Release All
              </Btn>
            </Panel>
          )}

          {/* PAYING */}
          {stage === "paying" && session && (
            <Panel>
              <PanelTitle style={{ color: "var(--warning)" }}>Payment</PanelTitle>

              <div style={{ display: "flex", gap: "0.35rem", flexWrap: "wrap", marginBottom: "0.875rem" }}>
                {session.seatIDs.map(id => (
                  <span key={id} style={{
                    fontSize: "0.72rem", fontWeight: 600,
                    background: "var(--held-mine)", color: "#000",
                    padding: "0.2rem 0.55rem", borderRadius: "4px",
                  }}>{id}</span>
                ))}
              </div>

              <InfoRow label="Total" value={fmt(showtime.price_cents * session.seatIDs.length, showtime.currency)} bold />

              <div style={{ margin: "0.875rem 0", textAlign: "center" }}>
                <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: "0.2rem" }}>
                  Pay within
                </div>
                <Countdown value={countdown(payExpiry!)} urgent={payLeft < 60} />
              </div>

              <Btn accent onClick={doConfirm} disabled={busy}>
                {busy ? "Processing…" : "✓ Pay Now"}
              </Btn>
              <Btn onClick={doRelease} disabled={busy} style={{ marginTop: "0.45rem" }}>
                Cancel
              </Btn>
            </Panel>
          )}

          {/* CONFIRMED */}
          {stage === "confirmed" && confirmed && (
            <Panel style={{ textAlign: "center" }}>
              <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}>🎟</div>
              <div style={{ fontWeight: 700, color: "var(--success)", marginBottom: "0.25rem" }}>
                Booking Confirmed!
              </div>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: "0.875rem" }}>
                #{confirmed.id.slice(0, 8).toUpperCase()}
              </div>
              <div style={{ display: "flex", gap: "0.35rem", justifyContent: "center", flexWrap: "wrap", marginBottom: "0.875rem" }}>
                {confirmed.seats.map(s => (
                  <span key={s.id} style={{
                    fontSize: "0.75rem", background: "var(--surface-2)",
                    color: "var(--success)", padding: "0.2rem 0.5rem", borderRadius: "4px",
                  }}>{s.id}</span>
                ))}
              </div>
              <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "var(--text)" }}>
                {fmt(confirmed.total_cents, showtime.currency)}
              </div>
              <div style={{ fontSize: "0.68rem", color: "var(--text-dim)", marginTop: "0.2rem" }}>paid</div>
            </Panel>
          )}

        </div>
      </div>
    </div>
  );

  function proceedToPayment() {
    setPayExpiry(Math.floor(Date.now() / 1000) + PAYMENT_TTL_S);
    setStage("paying");
  }
}

/* ── primitives ─────────────────────────────────────────────────── */

function Panel({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <div style={{
      background: "var(--surface)", border: "1px solid var(--border)",
      borderRadius: "8px", padding: "1.125rem", ...style,
    }}>
      {children}
    </div>
  );
}

function PanelTitle({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return <h3 style={{ fontSize: "0.8rem", fontWeight: 600, color: "var(--accent)", marginBottom: "0.75rem", ...style }}>{children}</h3>;
}

function InfoRow({ label, value, bold }: { label: string; value: string; bold?: boolean }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.76rem", marginBottom: "0.35rem" }}>
      <span style={{ color: "var(--text-muted)" }}>{label}</span>
      <span style={{ color: "var(--text)", fontWeight: bold ? 700 : 400 }}>{value}</span>
    </div>
  );
}

function Countdown({ value, urgent }: { value: string; urgent: boolean }) {
  return (
    <div style={{
      fontSize: "1.75rem", fontWeight: 700, letterSpacing: "0.04em",
      color: urgent ? "var(--danger)" : "var(--held-mine)", transition: "color 0.3s",
    }}>
      {value}
    </div>
  );
}

interface BtnProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  accent?: boolean;
  danger?: boolean;
}
function Btn({ children, accent, danger, style, disabled, ...rest }: BtnProps) {
  return (
    <button
      disabled={disabled}
      style={{
        display: "block", width: "100%",
        padding: "0.6rem", borderRadius: "6px", border: "none",
        fontFamily: "inherit", fontSize: "0.8rem", fontWeight: 600,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1, transition: "opacity 0.15s",
        background: accent ? "var(--accent)" : danger ? "var(--danger)" : "var(--surface-2)",
        color: accent ? "#000" : danger ? "#fff" : "var(--text-muted)",
        ...style,
      } as React.CSSProperties}
      {...rest}
    >
      {children}
    </button>
  );
}
