"use client";

import { useEffect, useState } from "react";
import { getAuthEmail, isAuthenticated } from "@/lib/auth";

function getOrCreateAnonID(): string {
  const stored = sessionStorage.getItem("cinebook_user_id");
  if (stored) return stored;
  const id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  sessionStorage.setItem("cinebook_user_id", id);
  return id;
}

export function UserBadge() {
  const [label, setLabel] = useState<string | null>(null);

  useEffect(() => {
    if (isAuthenticated()) {
      const email = getAuthEmail();
      setLabel(email ?? "signed in");
    } else {
      setLabel(`anon:${getOrCreateAnonID()}`);
    }
  }, []);

  if (!label) return null;

  return (
    <span
      className="text-xs px-2 py-1 rounded"
      style={{
        background: "var(--surface)", color: "var(--text-muted)",
        border: "1px solid var(--border)", fontFamily: "inherit",
        fontSize: "0.75rem",
      }}
    >
      {label}
    </span>
  );
}
