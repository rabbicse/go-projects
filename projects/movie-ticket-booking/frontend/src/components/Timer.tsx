"use client";

import { useEffect, useState } from "react";
import { Clock } from "lucide-react";

export function Timer({ expiresAt }: { expiresAt: number }) {
  const [remaining, setRemaining] = useState(() =>
    Math.max(0, expiresAt - Math.floor(Date.now() / 1000))
  );

  useEffect(() => {
    const id = setInterval(() => {
      setRemaining(Math.max(0, expiresAt - Math.floor(Date.now() / 1000)));
    }, 1000);
    return () => clearInterval(id);
  }, [expiresAt]);

  const mins = Math.floor(remaining / 60);
  const secs = remaining % 60;
  const urgent = remaining < 60;
  const label = `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;

  return (
    <div
      className="flex items-center gap-2 text-3xl font-mono font-bold tabular-nums transition-colors"
      style={{ color: urgent ? "#ef4444" : "var(--held-mine)" }}
    >
      <Clock size={24} className={urgent ? "animate-pulse" : ""} />
      {label}
    </div>
  );
}
