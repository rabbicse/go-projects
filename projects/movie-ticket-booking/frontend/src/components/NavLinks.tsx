"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { isAuthenticated, hasRole, logout } from "@/lib/auth";

export function NavLinks() {
  const [authed, setAuthed] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    const ok = isAuthenticated();
    setAuthed(ok);
    setIsAdmin(ok && hasRole("admin"));
  }, []);

  return (
    <>
      <Link href="/bookings" className="nav-link">My Bookings</Link>
      {authed ? (
        <>
          <Link href="/profile" className="nav-link">Profile</Link>
          {isAdmin && (
            <Link href="/admin/dashboard" className="nav-link">Admin</Link>
          )}
          <button
            onClick={() => void logout()}
            className="nav-link"
            style={{ background: "none", border: "none", cursor: "pointer", padding: 0, font: "inherit" }}
          >
            Sign out
          </button>
        </>
      ) : (
        <>
          <Link href="/login" className="nav-link">Login</Link>
          <Link href="/register" className="nav-link">Register</Link>
        </>
      )}
      <Link href="/api/v1/docs" target="_blank" rel="noopener noreferrer" className="nav-link">
        API Docs ↗
      </Link>
    </>
  );
}
