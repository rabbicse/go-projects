"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { api } from "@/lib/api";
import type { SeatStatus } from "@/types";

const ROWS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

export type SeatState = "available" | "held-mine" | "held-other" | "confirmed";

interface Props {
  showtimeId: string;
  rows: number;
  seatsPerRow: number;
  userID: string;
  /** optimistic local selection — shown as held-mine immediately */
  selectedSeats: string[];
  onClickSeat: (seatID: string, state: SeatState) => void;
  interactive: boolean;
}

export function SeatGrid({
  showtimeId, rows, seatsPerRow, userID,
  selectedSeats, onClickSeat, interactive,
}: Props) {
  const [statuses, setStatuses] = useState<Map<string, SeatStatus>>(new Map());
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStatuses = useCallback(async () => {
    try {
      const data = await api.showtimes.seats(showtimeId, userID);
      const map = new Map<string, SeatStatus>();
      for (const s of data) map.set(s.seat_id, s);
      setStatuses(map);
    } catch { /* swallow */ }
  }, [showtimeId, userID]);

  useEffect(() => {
    fetchStatuses();
    intervalRef.current = setInterval(fetchStatuses, 2000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [fetchStatuses]);

  function getState(seatID: string): SeatState {
    // Optimistic: locally-selected seats show as held-mine immediately
    if (selectedSeats.includes(seatID)) return "held-mine";
    const st = statuses.get(seatID);
    if (!st) return "available";
    if (st.status === "confirmed") return "confirmed";
    if (st.status === "held") return st.held_by_me ? "held-mine" : "held-other";
    return "available";
  }

  const colors: Record<SeatState, React.CSSProperties> = {
    available:    { background: "var(--seat-available)", color: "var(--text-muted)" },
    "held-mine":  { background: "var(--held-mine)",      color: "#000" },
    "held-other": { background: "var(--held-other)",     color: "#fff" },
    confirmed:    { background: "var(--confirmed)",       color: "#fff" },
  };

  function isClickable(state: SeatState): boolean {
    if (!interactive) return false;
    return state === "available" || state === "held-mine";
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "0.75rem" }}>
      {/* Screen */}
      <div style={{ textAlign: "center", width: "100%" }}>
        <div style={{ fontSize: "0.68rem", textTransform: "uppercase", letterSpacing: "0.15em", color: "var(--text-muted)", marginBottom: "0.35rem" }}>
          Screen
        </div>
        <div style={{ height: "3px", background: "linear-gradient(90deg, transparent, var(--accent), transparent)", margin: "0 3rem 1rem", borderRadius: "2px" }} />
      </div>

      {/* Grid */}
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "0.45rem" }}>
        {Array.from({ length: rows }, (_, r) => {
          const label = ROWS[r];
          return (
            <div key={label} style={{ display: "flex", alignItems: "center", gap: "0.45rem" }}>
              <span style={{ width: "1.4rem", textAlign: "center", fontSize: "0.65rem", color: "var(--text-muted)" }}>{label}</span>

              {Array.from({ length: seatsPerRow }, (_, s) => {
                const seatID = `${label}${s + 1}`;
                const state  = getState(seatID);
                const clickable = isClickable(state);
                return (
                  <button
                    key={seatID}
                    title={seatID}
                    onClick={() => clickable && onClickSeat(seatID, state)}
                    style={{
                      ...colors[state],
                      cursor: clickable ? "pointer" : state === "available" ? "default" : "not-allowed",
                      width: "34px", height: "30px",
                      borderRadius: "5px 5px 3px 3px",
                      border: "none",
                      fontSize: "0.62rem",
                      fontFamily: "inherit",
                      transition: "transform 0.12s, background 0.15s",
                      opacity: !interactive && state === "available" ? 0.45 : 1,
                    }}
                    onMouseEnter={(e) => { if (clickable) (e.currentTarget as HTMLElement).style.transform = "scale(1.1)"; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.transform = "scale(1)"; }}
                  >
                    {s + 1}
                  </button>
                );
              })}

              <span style={{ width: "1.4rem", textAlign: "center", fontSize: "0.65rem", color: "var(--text-muted)" }}>{label}</span>
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div style={{ display: "flex", gap: "1.2rem", justifyContent: "center", marginTop: "1rem", flexWrap: "wrap" }}>
        {[
          { label: "Available",  bg: "var(--seat-available)" },
          { label: "Your hold",  bg: "var(--held-mine)" },
          { label: "Other hold", bg: "var(--held-other)" },
          { label: "Confirmed",  bg: "var(--confirmed)" },
        ].map((item) => (
          <div key={item.label} style={{ display: "flex", alignItems: "center", gap: "0.35rem", fontSize: "0.68rem", color: "var(--text-muted)" }}>
            <div style={{ width: "13px", height: "11px", borderRadius: "3px 3px 2px 2px", background: item.bg }} />
            {item.label}
          </div>
        ))}
      </div>
    </div>
  );
}
