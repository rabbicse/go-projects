"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { api } from "@/lib/api";
import type { SeatStatus } from "@/types";

const ROWS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

interface Props {
  showtimeId: string;
  rows: number;
  seatsPerRow: number;
  userID: string;
  selectedSeats: string[];
  maxSeats: number;
  onToggleSeat: (seatID: string) => void;
  activeSessionSeats?: string[]; // seats in a held session (not selectable)
}

export function SeatGrid({
  showtimeId,
  rows,
  seatsPerRow,
  userID,
  selectedSeats,
  maxSeats,
  onToggleSeat,
  activeSessionSeats = [],
}: Props) {
  const [statuses, setStatuses] = useState<Map<string, SeatStatus>>(new Map());
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStatuses = useCallback(async () => {
    try {
      const data = await api.showtimes.seats(showtimeId, userID);
      const map = new Map<string, SeatStatus>();
      for (const s of data) map.set(s.seat_id, s);
      setStatuses(map);
    } catch {
      // polling — swallow errors silently
    }
  }, [showtimeId, userID]);

  useEffect(() => {
    fetchStatuses();
    intervalRef.current = setInterval(fetchStatuses, 2000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchStatuses]);

  function getSeatStyle(seatID: string): React.CSSProperties & { cursor: string } {
    const st = statuses.get(seatID);
    const isSelected = selectedSeats.includes(seatID);
    const isHeldByMe = st?.held_by_me || activeSessionSeats.includes(seatID);
    const isConfirmed = st?.status === "confirmed";
    const isHeldByOther = st?.status === "held" && !isHeldByMe;

    if (isConfirmed)
      return { background: "var(--confirmed)", color: "#fff", cursor: "not-allowed" };
    if (isHeldByOther)
      return { background: "var(--held-other)", color: "#fff", cursor: "not-allowed" };
    if (isHeldByMe)
      return { background: "var(--held-mine)", color: "#000", cursor: "default" };
    if (isSelected)
      return { background: "var(--accent)", color: "#fff", cursor: "pointer" };
    return { background: "var(--available)", color: "var(--text-muted)", cursor: "pointer" };
  }

  function canToggle(seatID: string): boolean {
    const st = statuses.get(seatID);
    if (st?.status === "confirmed") return false;
    if (st?.status === "held" && !st.held_by_me) return false;
    if (activeSessionSeats.includes(seatID)) return false;
    if (!selectedSeats.includes(seatID) && selectedSeats.length >= maxSeats) return false;
    return true;
  }

  return (
    <div className="space-y-4">
      {/* Screen */}
      <div className="text-center">
        <div
          className="text-xs uppercase tracking-widest mb-1"
          style={{ color: "var(--text-muted)" }}
        >
          Screen
        </div>
        <div
          className="h-1 mx-16 rounded-full"
          style={{
            background: "linear-gradient(90deg, transparent, var(--accent), transparent)",
          }}
        />
      </div>

      {/* Grid */}
      <div className="flex flex-col items-center gap-1.5">
        {Array.from({ length: rows }, (_, r) => {
          const rowLabel = ROWS[r];
          return (
            <div key={rowLabel} className="flex items-center gap-1.5">
              <span
                className="w-5 text-center text-xs font-mono"
                style={{ color: "var(--text-muted)" }}
              >
                {rowLabel}
              </span>
              {Array.from({ length: seatsPerRow }, (_, s) => {
                const seatID = `${rowLabel}${s + 1}`;
                const style = getSeatStyle(seatID);
                const clickable = canToggle(seatID);
                return (
                  <button
                    key={seatID}
                    onClick={() => clickable && onToggleSeat(seatID)}
                    title={seatID}
                    style={style}
                    className="w-8 h-7 rounded-t-lg rounded-b-sm text-xs font-mono font-medium transition-transform hover:scale-110 disabled:scale-100 border border-transparent"
                  >
                    {s + 1}
                  </button>
                );
              })}
              <span
                className="w-5 text-center text-xs font-mono"
                style={{ color: "var(--text-muted)" }}
              >
                {rowLabel}
              </span>
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap justify-center gap-4 pt-2">
        {[
          { label: "Available", bg: "var(--available)" },
          { label: "Selected", bg: "var(--accent)" },
          { label: "Your hold", bg: "var(--held-mine)" },
          { label: "Held", bg: "var(--held-other)" },
          { label: "Confirmed", bg: "var(--confirmed)" },
        ].map((item) => (
          <div key={item.label} className="flex items-center gap-1.5 text-xs" style={{ color: "var(--text-muted)" }}>
            <div
              className="w-4 h-3 rounded-sm"
              style={{ background: item.bg }}
            />
            {item.label}
          </div>
        ))}
      </div>
    </div>
  );
}
