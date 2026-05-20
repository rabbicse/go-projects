"use client";

import { useEffect, useState } from "react";

function getOrCreateUserID(): string {
  const stored = sessionStorage.getItem("cinebook_user_id");
  if (stored) return stored;
  const id = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  sessionStorage.setItem("cinebook_user_id", id);
  return id;
}

export function UserBadge() {
  const [userID, setUserID] = useState<string | null>(null);

  useEffect(() => {
    setUserID(getOrCreateUserID());
  }, []);

  if (!userID) return null;

  return (
    <span
      className="text-xs px-2 py-1 rounded"
      style={{ background: "var(--surface)", color: "var(--text-muted)", border: "1px solid var(--border)", fontFamily: "inherit" }}
    >
      user: {userID}
    </span>
  );
}
