"use client";

import { use, useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import { SeatGrid, type SeatState } from "@/components/SeatGrid";
import type { ActiveSession, BookingResponse, Showtime } from "@/types";

const MAX_SEATS      = parseInt(process.env.NEXT_PUBLIC_MAX_SEATS ?? "4", 10);
const PAYMENT_TTL_S  = 180;
const SYNC_DEBOUNCE_MS = 300; // wait for click burst to settle before hitting the API

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
  const [selected,  setSelected]  = useState<string[]>([]);
  const [session,   setSession]   = useState<ActiveSession | null>(null);
  const [payExpiry, setPayExpiry] = useState<number | null>(null);
  const [confirmed, setConfirmed] = useState<BookingResponse | null>(null);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [tick,      setTick]      = useState(0);

  // ── payment card form state ────────────────────────────────────
  const [cardNum,    setCardNum]    = useState("");
  const [cardExpiry, setCardExpiry] = useState("");
  const [cardCVV,    setCardCVV]    = useState("");

  /**
   * busy: true during explicit user actions (Release All, Pay Now).
   * Disables buttons to prevent double-submit.
   *
   * syncing: true from the moment a seat click schedules a debounced API call
   * until that call completes. Seat clicks remain active while syncing — each
   * new click cancels the previous debounce and reschedules (click-burst batching).
   * Action buttons (Proceed, Release) are disabled while syncing.
   */
  const [busy,    setBusy]    = useState(false);
  const [syncing, setSyncing] = useState(false);

  const sessionRef  = useRef(session);
  sessionRef.current = session;

  // Debounce + generation counter for background seat sync.
  // Generation prevents stale async results from overwriting current state.
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const syncGenRef  = useRef(0);

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
  function showError(e: unknown, ms = 3000) {
    const msg = e instanceof Error ? e.message : "Error";
    setActionErr(msg);
    setTimeout(() => setActionErr(null), ms);
  }

  // ── background seat-hold sync (called after debounce settles) ──
  //
  // Each invocation is stamped with a generation number. If a newer sync
  // supersedes this one (user clicked again during the API call), we return
  // early and leave state untouched. The superseded hold expires via TTL.
  const syncHold = useCallback(async (seats: string[], gen: number) => {
    const prev = sessionRef.current;

    try {
      // Release previous session before placing a new hold
      if (prev) {
        try { await api.sessions.release(prev.sessionID, userID); } catch { /* already expired */ }
        if (syncGenRef.current !== gen) return; // superseded
        setSession(null);
      }

      if (seats.length === 0) {
        if (syncGenRef.current !== gen) return;
        setStage("browse");
        return;
      }

      const res = await api.showtimes.hold(showtimeId, userID, seats);
      if (syncGenRef.current !== gen) return; // superseded — orphan hold expires via TTL

      setSession({
        sessionID:  res.session_id,
        showtimeID: res.showtime_id,
        movieID:    res.movie_id,
        seatIDs:    res.seat_ids,
        expiresAt:  res.expires_at,
      });
      setStage("checkout");
      setActionErr(null);
    } catch (e) {
      if (syncGenRef.current !== gen) return;
      // Rollback the optimistic selection to the previous hold's seats
      setSelected(prev?.seatIDs ?? []);
      setStage(prev ? "checkout" : "browse");
      showError(e);
    } finally {
      if (syncGenRef.current === gen) setSyncing(false);
    }
  }, [showtimeId, userID]);

  // ── seat click handler ─────────────────────────────────────────
  //
  // BEFORE: each click set busy=true, ran a sequential release+hold (~400ms),
  //         then set busy=false. All clicks during that window were ignored.
  //
  // AFTER:  each click updates local state instantly (zero latency), then
  //         schedules a debounced API sync. Rapid clicks cancel the previous
  //         debounce — the API is called only once after the burst settles.
  function handleSeatClick(seatID: string, state: SeatState) {
    if (stage === "paying" || stage === "confirmed") return;
    if (busy) return; // still blocked during explicit release/confirm operations

    let next: string[];
    if (state === "available") {
      if (selected.length >= MAX_SEATS) return;
      next = [...selected, seatID];
    } else if (state === "held-mine") {
      next = selected.filter(s => s !== seatID);
    } else {
      return;
    }

    // 1. Instant optimistic update — no network, no busy flag
    setSelected(next);
    setSyncing(true);

    // 2. Short-circuit: nothing on server to sync if no session and no seats
    if (next.length === 0 && !sessionRef.current) {
      setStage("browse");
      setSyncing(false);
      return;
    }

    // 3. Debounce: cancel any pending sync and reschedule
    if (debounceRef.current) clearTimeout(debounceRef.current);
    const gen = ++syncGenRef.current;
    debounceRef.current = setTimeout(() => syncHold(next, gen), SYNC_DEBOUNCE_MS);
  }

  // ── doRelease ─────────────────────────────────────────────────
  const doRelease = useCallback(async () => {
    // Cancel any pending debounce and mark in-flight sync as stale
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
      debounceRef.current = null;
    }
    ++syncGenRef.current;
    setBusy(true);
    setSyncing(false);

    const s = sessionRef.current;
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
    if (!s || busy || !showtime) return;
    setBusy(true);
    setActionErr(null);
    try {
      const result = await api.sessions.pay(s.sessionID, userID, {
        card_number: cardNum,
        expiry: cardExpiry,
        cvv: cardCVV,
        amount_cents: showtime.price_cents * s.seatIDs.length,
        currency: showtime.currency,
      });
      setConfirmed(result.booking);
      setSession(null);
      setSelected([]);
      setStage("confirmed");
      setPayExpiry(null);
    } catch (e) {
      showError(e);
    } finally {
      setBusy(false);
    }
  }

  function proceedToPayment() {
    // Cancel any pending seat sync — seat set is final at this point
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
      debounceRef.current = null;
    }
    ++syncGenRef.current;
    setSyncing(false);
    setPayExpiry(Math.floor(Date.now() / 1000) + PAYMENT_TTL_S);
    setStage("paying");
  }

  // ── render ────────────────────────────────────────────────────
  if (loading)  return <p style={{ textAlign: "center", padding: "6rem", color: "var(--text-muted)" }}>Loading…</p>;
  if (fetchErr || !showtime) return <p style={{ textAlign: "center", padding: "6rem", color: "var(--danger)" }}>{fetchErr ?? "Not found"}</p>;

  const holdLeft = session ? Math.max(0, session.expiresAt - Math.floor(Date.now() / 1000)) : 0;
  const payLeft  = payExpiry ? Math.max(0, payExpiry - Math.floor(Date.now() / 1000)) : 0;
  const actionBusy = busy || syncing; // used to disable action buttons

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
          {/* Sync indicator — non-blocking, purely informational */}
          {syncing && (
            <p style={{
              textAlign: "center", marginTop: "0.5rem",
              fontSize: "0.65rem", color: "var(--text-dim)", letterSpacing: "0.04em",
            }}>
              syncing…
            </p>
          )}
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
          {(stage === "checkout" || (stage === "browse" && selected.length > 0)) && (
            <Panel>
              <PanelTitle>Checkout</PanelTitle>

              {/* Selected seats chips */}
              <div style={{ display: "flex", gap: "0.35rem", flexWrap: "wrap", marginBottom: "0.875rem" }}>
                {selected.map(id => (
                  <span key={id} style={{
                    fontSize: "0.72rem", fontWeight: 600,
                    background: "var(--held-mine)", color: "#000",
                    padding: "0.2rem 0.55rem", borderRadius: "4px",
                  }}>{id}</span>
                ))}
              </div>

              <InfoRow label="Price" value={fmt(showtime.price_cents * selected.length, showtime.currency)} bold />
              {session && <InfoRow label="Session" value={session.sessionID.slice(0, 8) + "…"} />}

              {session && (
                <div style={{ margin: "0.875rem 0", textAlign: "center" }}>
                  <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: "0.2rem" }}>
                    Hold expires in
                  </div>
                  <Countdown value={countdown(session.expiresAt)} urgent={holdLeft < 60} />
                </div>
              )}

              <p style={{ fontSize: "0.68rem", color: "var(--text-dim)", marginBottom: "0.875rem", textAlign: "center" }}>
                Click a gold seat to remove it &bull; click available seat to add
              </p>

              <Btn accent onClick={proceedToPayment} disabled={actionBusy}>
                {syncing ? "Syncing…" : "Proceed to Payment →"}
              </Btn>
              <Btn danger onClick={doRelease} disabled={actionBusy} style={{ marginTop: "0.45rem" }}>
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

              <div style={{ margin: "0.75rem 0", textAlign: "center" }}>
                <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: "0.2rem" }}>Pay within</div>
                <Countdown value={countdown(payExpiry!)} urgent={payLeft < 60} />
              </div>

              {/* Card form */}
              <CardInput label="Card number" value={cardNum} onChange={setCardNum} placeholder="1234 5678 9012 3456" maxLen={19} disabled={busy} />
              <div style={{ display: "flex", gap: "0.45rem" }}>
                <CardInput label="Expiry" value={cardExpiry} onChange={setCardExpiry} placeholder="MM/YY" maxLen={5} disabled={busy} />
                <CardInput label="CVV" value={cardCVV} onChange={setCardCVV} placeholder="123" maxLen={4} disabled={busy} />
              </div>
              <p style={{ fontSize: "0.65rem", color: "var(--text-dim)", marginBottom: "0.75rem", marginTop: "-0.25rem" }}>
                Test: any card not ending in 0000 succeeds.
              </p>

              <Btn
                accent
                onClick={doConfirm}
                disabled={busy || !cardNum.trim() || !cardExpiry.trim() || !cardCVV.trim()}
              >
                {busy ? "Processing…" : `Pay ${fmt(showtime.price_cents * session.seatIDs.length, showtime.currency)}`}
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

function CardInput({ label, value, onChange, placeholder, maxLen, disabled }: {
  label: string; value: string; onChange: (v: string) => void;
  placeholder: string; maxLen: number; disabled: boolean;
}) {
  return (
    <div style={{ flex: 1, marginBottom: "0.5rem" }}>
      <label style={{ display: "block", fontSize: "0.65rem", color: "var(--text-muted)", marginBottom: "0.2rem" }}>{label}</label>
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        maxLength={maxLen}
        disabled={disabled}
        style={{
          width: "100%", padding: "0.45rem 0.55rem",
          border: "1px solid var(--border)", borderRadius: "5px",
          background: "var(--surface-2)", color: "var(--text)",
          fontSize: "0.78rem", fontFamily: "inherit",
          boxSizing: "border-box" as const,
        }}
      />
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
