"use client";

import { useState } from "react";
import { Ticket, CheckCircle, XCircle, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { Timer } from "./Timer";
import type { ActiveSession, BookingResponse } from "@/types";

interface Props {
  session: ActiveSession;
  userID: string;
  priceCents: number;
  currency: string;
  onConfirmed: (booking: BookingResponse) => void;
  onReleased: () => void;
  maxSeats: number;
}

export function Checkout({
  session,
  userID,
  priceCents,
  currency,
  onConfirmed,
  onReleased,
  maxSeats,
}: Props) {
  const [state, setState] = useState<"idle" | "confirming" | "releasing" | "confirmed" | "released">("idle");
  const [error, setError] = useState<string | null>(null);
  const [confirmedBooking, setConfirmedBooking] = useState<BookingResponse | null>(null);

  const totalCents = priceCents * session.seatIDs.length;
  const fmt = (c: number) =>
    new Intl.NumberFormat("en-US", { style: "currency", currency }).format(c / 100);

  async function handleConfirm() {
    setState("confirming");
    setError(null);
    try {
      const booking = await api.sessions.confirm(session.sessionID, userID);
      setConfirmedBooking(booking);
      setState("confirmed");
      onConfirmed(booking);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Confirm failed");
      setState("idle");
    }
  }

  async function handleRelease() {
    setState("releasing");
    setError(null);
    try {
      await api.sessions.release(session.sessionID, userID);
      setState("released");
      onReleased();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Release failed");
      setState("idle");
    }
  }

  if (state === "confirmed" && confirmedBooking) {
    return (
      <div
        className="rounded-xl border p-6 space-y-3 text-center"
        style={{ background: "var(--surface)", borderColor: "#22c55e33" }}
      >
        <CheckCircle size={40} className="mx-auto" style={{ color: "var(--success)" }} />
        <h3 className="font-bold text-lg" style={{ color: "var(--success)" }}>
          Booking Confirmed!
        </h3>
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Booking ID: <span className="font-mono text-xs">{confirmedBooking.id.slice(0, 12)}…</span>
        </p>
        <div className="text-sm space-y-1">
          {confirmedBooking.seats.map((s) => (
            <span
              key={s.id}
              className="inline-block mx-1 px-2 py-0.5 rounded font-mono text-xs"
              style={{ background: "var(--surface-2)", color: "var(--success)" }}
            >
              {s.id}
            </span>
          ))}
        </div>
        <p className="font-bold text-xl" style={{ color: "var(--text)" }}>
          {fmt(confirmedBooking.total_cents)}
        </p>
      </div>
    );
  }

  return (
    <div
      className="rounded-xl border p-6 space-y-4"
      style={{ background: "var(--surface)", borderColor: "var(--border)" }}
    >
      <div className="flex items-center gap-2">
        <Ticket size={18} style={{ color: "var(--accent)" }} />
        <h3 className="font-bold text-sm" style={{ color: "var(--accent)" }}>
          Checkout
        </h3>
        <span className="ml-auto text-xs" style={{ color: "var(--text-muted)" }}>
          {session.seatIDs.length}/{maxSeats} seats
        </span>
      </div>

      {/* Timer */}
      <div
        className="rounded-lg p-3 text-center"
        style={{ background: "var(--surface-2)" }}
      >
        <div className="text-xs mb-1" style={{ color: "var(--text-muted)" }}>
          Hold expires in
        </div>
        <Timer expiresAt={session.expiresAt} />
      </div>

      {/* Seat list */}
      <div className="space-y-1">
        {session.seatIDs.map((id) => (
          <div
            key={id}
            className="flex items-center justify-between text-sm py-1 border-b"
            style={{ borderColor: "var(--border)" }}
          >
            <span className="font-mono" style={{ color: "var(--text)" }}>
              Seat {id}
            </span>
            <span style={{ color: "var(--text-muted)" }}>{fmt(priceCents)}</span>
          </div>
        ))}
        <div className="flex items-center justify-between text-sm pt-1 font-bold">
          <span style={{ color: "var(--text)" }}>Total</span>
          <span style={{ color: "var(--accent)" }}>{fmt(totalCents)}</span>
        </div>
      </div>

      {error && (
        <p className="text-xs text-center" style={{ color: "var(--confirmed)" }}>
          {error}
        </p>
      )}

      {/* Buttons */}
      <div className="grid grid-cols-2 gap-2">
        <button
          onClick={handleConfirm}
          disabled={state !== "idle"}
          className="flex items-center justify-center gap-1.5 py-2.5 rounded-lg text-sm font-semibold transition-opacity disabled:opacity-50"
          style={{ background: "var(--success)", color: "#fff" }}
        >
          {state === "confirming" ? (
            <Loader2 size={16} className="animate-spin" />
          ) : (
            <CheckCircle size={16} />
          )}
          Confirm
        </button>
        <button
          onClick={handleRelease}
          disabled={state !== "idle"}
          className="flex items-center justify-center gap-1.5 py-2.5 rounded-lg text-sm font-semibold transition-opacity disabled:opacity-50"
          style={{ background: "var(--surface-2)", color: "var(--text-muted)", border: "1px solid var(--border)" }}
        >
          {state === "releasing" ? (
            <Loader2 size={16} className="animate-spin" />
          ) : (
            <XCircle size={16} />
          )}
          Release
        </button>
      </div>
    </div>
  );
}
