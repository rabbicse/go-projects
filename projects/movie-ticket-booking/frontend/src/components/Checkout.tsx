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

type CheckoutState = "idle" | "payment-form" | "processing" | "releasing";

export function Checkout({ session, userID, priceCents, currency, onConfirmed, onReleased }: Props) {
  const [state, setState] = useState<CheckoutState>("idle");
  const [error, setError] = useState<string | null>(null);
  const [card, setCard] = useState({ number: "", expiry: "", cvv: "" });

  const total = priceCents * session.seatIDs.length;
  const fmt = (c: number) =>
    new Intl.NumberFormat("en-US", { style: "currency", currency }).format(c / 100);

  async function handlePay() {
    setState("processing");
    setError(null);
    try {
      const result = await api.sessions.pay(session.sessionID, userID, {
        card_number: card.number,
        expiry: card.expiry,
        cvv: card.cvv,
        amount_cents: total,
        currency,
      });
      onConfirmed(result.booking);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Payment failed");
      setState("payment-form");
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

  const infoLabel: React.CSSProperties = { color: "var(--text-muted)" };

  const inputStyle: React.CSSProperties = {
    width: "100%",
    padding: "0.5rem 0.6rem",
    border: "1px solid var(--border)",
    borderRadius: "6px",
    background: "var(--background)",
    color: "var(--text)",
    fontSize: "0.8rem",
    fontFamily: "inherit",
    boxSizing: "border-box",
    marginBottom: "0.75rem",
  };

  const btnBase: React.CSSProperties = {
    flex: 1,
    padding: "0.6rem",
    border: "none",
    borderRadius: "6px",
    fontFamily: "inherit",
    fontSize: "0.8rem",
    fontWeight: 600,
    transition: "opacity 0.2s",
  };

  // --- Payment form view ---
  if (state === "payment-form" || state === "processing") {
    const busy = state === "processing";
    const canPay = !busy && card.number.trim() !== "" && card.expiry.trim() !== "" && card.cvv.trim() !== "";

    return (
      <div style={box}>
        <h3 style={{ fontSize: "0.85rem", marginBottom: "0.75rem", color: "var(--accent)" }}>
          Payment
        </h3>
        <div style={{ ...infoRow, marginBottom: "1rem" }}>
          <span style={infoLabel}>Total: </span>
          <strong>{fmt(total)}</strong>
        </div>

        <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", display: "block", marginBottom: "0.25rem" }}>
          Card number
        </label>
        <input
          type="text"
          placeholder="1234 5678 9012 3456"
          value={card.number}
          onChange={(e) => setCard({ ...card, number: e.target.value })}
          disabled={busy}
          maxLength={19}
          style={inputStyle}
        />

        <div style={{ display: "flex", gap: "0.6rem" }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", display: "block", marginBottom: "0.25rem" }}>
              Expiry (MM/YY)
            </label>
            <input
              type="text"
              placeholder="MM/YY"
              value={card.expiry}
              onChange={(e) => setCard({ ...card, expiry: e.target.value })}
              disabled={busy}
              maxLength={5}
              style={inputStyle}
            />
          </div>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: "0.75rem", color: "var(--text-muted)", display: "block", marginBottom: "0.25rem" }}>
              CVV
            </label>
            <input
              type="text"
              placeholder="123"
              value={card.cvv}
              onChange={(e) => setCard({ ...card, cvv: e.target.value })}
              disabled={busy}
              maxLength={4}
              style={inputStyle}
            />
          </div>
        </div>

        <div style={{ fontSize: "0.7rem", color: "var(--text-muted)", marginBottom: "0.75rem" }}>
          Test: any card not ending in 0000 succeeds.
        </div>

        {error && (
          <div style={{ fontSize: "0.8rem", fontWeight: 600, color: "var(--danger)", textAlign: "center", marginBottom: "0.75rem" }}>
            {error}
          </div>
        )}

        <div style={{ display: "flex", gap: "0.6rem" }}>
          <button
            onClick={handlePay}
            disabled={!canPay}
            style={{ ...btnBase, background: "#27ae60", color: "#fff", cursor: canPay ? "pointer" : "not-allowed", opacity: canPay ? 1 : 0.6 }}
          >
            {busy ? "Processing…" : `Pay ${fmt(total)}`}
          </button>
          <button
            onClick={() => { setState("idle"); setError(null); }}
            disabled={busy}
            style={{ padding: "0.6rem", border: "1px solid var(--border)", borderRadius: "6px", fontFamily: "inherit", fontSize: "0.8rem", cursor: busy ? "not-allowed" : "pointer", background: "transparent", color: "var(--text-muted)", opacity: busy ? 0.6 : 1 }}
          >
            Back
          </button>
        </div>
      </div>
    );
  }

  // --- Idle view ---
  const busy = state === "releasing";
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
        {fmt(total)}
      </div>
      <div style={infoRow}>
        <span style={infoLabel}>Session: </span>
        {session.sessionID.slice(0, 8)}…
      </div>

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
          onClick={() => setState("payment-form")}
          disabled={busy}
          style={{ ...btnBase, background: "#27ae60", color: "#fff", cursor: busy ? "not-allowed" : "pointer", opacity: busy ? 0.6 : 1 }}
        >
          Pay Now
        </button>
        <button
          onClick={handleRelease}
          disabled={busy}
          style={{ ...btnBase, background: "var(--danger)", color: "#fff", cursor: busy ? "not-allowed" : "pointer", opacity: busy ? 0.6 : 1 }}
        >
          {busy ? "Releasing…" : "Release"}
        </button>
      </div>
    </div>
  );
}
