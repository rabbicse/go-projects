"use client";

import { useEffect, useRef, useState } from "react";

interface Props {
  expiresAt: number; // unix seconds
  onExpired?: () => void;
}

export function Timer({ expiresAt, onExpired }: Props) {
  const [remaining, setRemaining] = useState(() =>
    Math.max(0, expiresAt - Math.floor(Date.now() / 1000))
  );
  const onExpiredRef = useRef(onExpired);
  onExpiredRef.current = onExpired;

  useEffect(() => {
    const id = setInterval(() => {
      const left = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
      setRemaining(left);
      if (left === 0) {
        clearInterval(id);
        onExpiredRef.current?.();
      }
    }, 1000);
    return () => clearInterval(id);
  }, [expiresAt]);

  const mins = Math.floor(remaining / 60);
  const secs = remaining % 60;
  const urgent = remaining < 60;
  const label = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;

  return (
    <div
      style={{
        fontSize: "1.8rem",
        fontWeight: 700,
        fontFamily: "inherit",
        textAlign: "center",
        color: urgent ? "var(--danger)" : "var(--held-mine)",
        transition: "color 0.3s",
        letterSpacing: "0.05em",
      }}
    >
      {label}
    </div>
  );
}
