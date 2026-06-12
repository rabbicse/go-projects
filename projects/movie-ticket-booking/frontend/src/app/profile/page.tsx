"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { getAccessToken, isAuthenticated, logout } from "@/lib/auth";

interface UserProfile {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  roles: string[];
  created_at: string;
}

async function fetchProfile(): Promise<UserProfile> {
  const token = getAccessToken();
  if (!token) throw new Error("Not authenticated");
  const res = await fetch("/api/v1/auth/profile", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 401) throw new Error("Session expired — please sign in again");
  if (!res.ok) throw new Error("Failed to load profile");
  return res.json() as Promise<UserProfile>;
}

const fieldStyle: React.CSSProperties = {
  padding: "0.75rem 1rem", borderRadius: "8px",
  border: "1px solid var(--border)", background: "var(--surface)", marginBottom: "0.75rem",
};
const labelStyle: React.CSSProperties = {
  fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: "0.2rem",
  textTransform: "uppercase", letterSpacing: "0.05em",
};
const valueStyle: React.CSSProperties = { fontSize: "0.9rem", color: "var(--text)" };

export default function ProfilePage() {
  const authed = typeof window !== "undefined" ? isAuthenticated() : false;

  const { data, isLoading, error } = useQuery<UserProfile, Error>({
    queryKey: ["profile"],
    queryFn: fetchProfile,
    enabled: authed,
    retry: false,
  });

  if (!authed) {
    return (
      <div className="page-container" style={{ paddingTop: "4rem", maxWidth: "400px" }}>
        <h1 style={{ fontSize: "1.4rem", fontWeight: 700, marginBottom: "1rem" }}>Profile</h1>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "1.5rem" }}>
          You are not signed in.
        </p>
        <Link href="/login" style={{
          padding: "0.6rem 1.2rem", borderRadius: "7px", background: "var(--accent)",
          color: "#fff", fontSize: "0.85rem", textDecoration: "none",
        }}>
          Sign in
        </Link>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="page-container" style={{ paddingTop: "4rem" }}>
        <p style={{ color: "var(--text-muted)" }}>Loading profile…</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="page-container" style={{ paddingTop: "4rem", maxWidth: "400px" }}>
        <p style={{ color: "var(--danger)", marginBottom: "1rem" }}>
          {error?.message ?? "Could not load profile"}
        </p>
        <Link href="/login" style={{ color: "var(--accent)" }}>Sign in again</Link>
      </div>
    );
  }

  const displayName = [data.first_name, data.last_name].filter(Boolean).join(" ") || data.email;

  return (
    <div className="page-container" style={{ paddingTop: "4rem", maxWidth: "480px" }}>
      <h1 style={{ fontSize: "1.4rem", fontWeight: 700, marginBottom: "2rem" }}>
        {displayName}
      </h1>

      <div style={fieldStyle}>
        <p style={labelStyle}>Email</p>
        <p style={valueStyle}>{data.email}</p>
      </div>

      <div style={fieldStyle}>
        <p style={labelStyle}>User ID</p>
        <p style={{ ...valueStyle, fontFamily: "monospace", fontSize: "0.8rem", wordBreak: "break-all" }}>
          {data.id}
        </p>
      </div>

      <div style={fieldStyle}>
        <p style={labelStyle}>Member since</p>
        <p style={valueStyle}>{new Date(data.created_at).toLocaleDateString()}</p>
      </div>

      <div style={fieldStyle}>
        <p style={labelStyle}>Roles</p>
        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "0.25rem" }}>
          {data.roles.map((r) => (
            <span key={r} style={{
              padding: "0.2rem 0.6rem", borderRadius: "4px",
              background: r === "admin" ? "var(--accent)" : "var(--border)",
              color: r === "admin" ? "#fff" : "var(--text)",
              fontSize: "0.78rem", fontWeight: 600,
            }}>
              {r}
            </span>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", gap: "0.75rem", marginTop: "1.5rem" }}>
        <Link href="/bookings" style={{
          padding: "0.6rem 1.2rem", borderRadius: "7px", background: "var(--accent)",
          color: "#fff", fontSize: "0.85rem", textDecoration: "none",
        }}>
          My bookings
        </Link>
        <button
          onClick={() => void logout()}
          style={{
            padding: "0.6rem 1.2rem", borderRadius: "7px", border: "1px solid var(--border)",
            background: "var(--surface)", color: "var(--text)", cursor: "pointer", fontSize: "0.85rem",
          }}
        >
          Sign out
        </button>
      </div>
    </div>
  );
}
