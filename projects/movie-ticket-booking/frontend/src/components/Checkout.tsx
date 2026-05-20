"use client";

import { useState } from "react";
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

export function Checkout({ session, userID, priceCents, currency, onConfirmed, onReleased }: Props) {
  const [state, setState] = useState<"idle" | "confirming" | "releasing">("idle");
  const [error, setError] = useState<string | null>(null);

  const fmt = (c: number) =>
    new Intl.NumberFormat("en-US", { style: "currency", currency }).format(c / 100);

  async function handleConfirm() {
    setState("confirming");
    setError(null);
    try {
      const booking = await api.sessions.confirm(session.sessionID, userID);
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
      onReleased();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Release failed");
      setState("idle");
    }
  }

  const box: React.CSSProperties = {
    background: "var(--surface)",
    border: "1px solid var(--border)",
    borderRadius: "8px",
    padding: "1.4rem",
  };

  const infoRow: React.CSSProperties = {
    fontSize: "0.8rem",
    marginBottom: "0.5rem",
    color: "var(--text)",
  };

  const infoLabel: React.CSSProperties = {
    color: "var(--text-muted)",
  };

  return (
    <div style={box}>
      <h3 style={{ fontSize: "0.85rem", marginBottom: "1rem", color: "var(--accent)" }}>
        Checkout
      </h3>

      <div style={infoRow}>
        <span style={infoLabel}>Seat{session.seatIDs.length > 1 ? "s" : ""}: </span>
        {session.seatIDs.join(", ")}
      </div>
      <div style={infoRow}>
        <span style={infoLabel}>Price: </span>
        {fmt(priceCents * session.seatIDs.length)}
      </div>
      <div style={infoRow}>
        <span style={infoLabel}>Session: </span>
        {session.sessionID.slice(0, 8)}…
      </div>

      {/* Countdown timer */}
      <div style={{ margin: "1rem 0", textAlign: "center" }}>
        <Timer expiresAt={session.expiresAt} onExpired={onReleased} />
      </div>

      {error && (
        <div style={{ fontSize: "0.8rem", fontWeight: 600, color: "var(--danger)", textAlign: "center", marginBottom: "0.75rem" }}>
          {error}
        </div>
      )}

      <div style={{ display: "flex", gap: "0.6rem" }}>
        <button
          onClick={handleConfirm}
          disabled={state !== "idle"}
          style={{
            flex: 1,
            padding: "0.6rem",
            border: "none",
            borderRadius: "6px",
            fontFamily: "inherit",
            fontSize: "0.8rem",
            fontWeight: 600,
            cursor: state !== "idle" ? "not-allowed" : "pointer",
            background: "#27ae60",
            color: "#fff",
            opacity: state !== "idle" ? 0.6 : 1,
            transition: "opacity 0.2s",
          }}
        >
          {state === "confirming" ? "Confirming…" : "Confirm"}
        </button>
        <button
          onClick={handleRelease}
          disabled={state !== "idle"}
          style={{
            flex: 1,
            padding: "0.6rem",
            border: "none",
            borderRadius: "6px",
            fontFamily: "inherit",
            fontSize: "0.8rem",
            fontWeight: 600,
            cursor: state !== "idle" ? "not-allowed" : "pointer",
            background: "var(--danger)",
            color: "#fff",
            opacity: state !== "idle" ? 0.6 : 1,
            transition: "opacity 0.2s",
          }}
        >
          {state === "releasing" ? "Releasing…" : "Release"}
        </button>
      </div>
    </div>
  );
}
