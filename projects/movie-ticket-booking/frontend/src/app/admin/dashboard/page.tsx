"use client";

import { useQuery } from "@tanstack/react-query";
import { Film, Clock, Ticket, DollarSign, BarChart3, CalendarDays, Loader2 } from "lucide-react";
import { getAccessToken } from "@/lib/auth";

interface AdminStats {
  total_movies: number;
  total_showtimes: number;
  total_seats: number;
  total_confirmed_bookings: number;
  total_revenue_cents: number;
}

async function fetchStats(): Promise<AdminStats> {
  const token = getAccessToken();
  const res = await fetch("/api/v1/admin/stats", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error("Failed to load stats");
  return res.json() as Promise<AdminStats>;
}

function fmtCents(c: number) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(c / 100);
}

const futureModules = [
  {
    icon: Film,
    label: "Movies",
    description: "Manage the movie catalogue — add, edit, and archive titles.",
    href: "/admin/movies",
  },
  {
    icon: CalendarDays,
    label: "Shows",
    description: "Schedule showtimes, assign halls, and set capacity.",
    href: "/admin/shows",
  },
  {
    icon: DollarSign,
    label: "Pricing",
    description: "Configure seat tiers, dynamic pricing rules, and promotions.",
    href: "/admin/pricing",
  },
  {
    icon: BarChart3,
    label: "Analytics",
    description: "Revenue reports, seat fill-rate, and booking trends.",
    href: "/admin/analytics",
  },
];

export default function DashboardPage() {
  const { data: stats, isLoading, error } = useQuery<AdminStats, Error>({
    queryKey: ["admin", "stats"],
    queryFn: fetchStats,
    retry: 1,
  });

  const statCards = stats
    ? [
        { label: "Movies", value: stats.total_movies, icon: Film, color: "var(--accent)" },
        { label: "Showtimes", value: stats.total_showtimes, icon: Clock, color: "var(--warning)" },
        { label: "Total seats", value: stats.total_seats.toLocaleString(), icon: Ticket, color: "var(--success)" },
        { label: "Confirmed bookings", value: stats.total_confirmed_bookings, icon: Ticket, color: "var(--success)" },
        { label: "Revenue", value: fmtCents(stats.total_revenue_cents), icon: DollarSign, color: "#27ae60" },
      ]
    : [];

  return (
    <div>
      {/* Page header */}
      <div style={{ marginBottom: "2rem" }}>
        <h1 style={{ fontSize: "1.5rem", fontWeight: 700, color: "var(--text)", marginBottom: "0.25rem" }}>
          Dashboard
        </h1>
        <p style={{ fontSize: "0.83rem", color: "var(--text-muted)" }}>
          Overview of your cinema operations.
        </p>
      </div>

      {/* Stats */}
      {isLoading && (
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", color: "var(--text-muted)", marginBottom: "2rem" }}>
          <Loader2 size={16} className="animate-spin" />
          <span style={{ fontSize: "0.83rem" }}>Loading stats…</span>
        </div>
      )}

      {error && (
        <div
          style={{
            padding: "0.75rem 1rem", borderRadius: "8px", marginBottom: "2rem",
            border: "1px solid var(--danger)",
            background: "color-mix(in srgb, var(--danger) 10%, transparent)",
            fontSize: "0.83rem", color: "var(--danger)",
          }}
        >
          {error.message} — make sure the backend is running with JWT_SECRET set.
        </div>
      )}

      {stats && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))",
            gap: "1rem",
            marginBottom: "2.5rem",
          }}
        >
          {statCards.map((s) => (
            <div
              key={s.label}
              style={{
                padding: "1rem",
                borderRadius: "10px",
                border: "1px solid var(--border)",
                background: "var(--surface-2)",
                display: "flex",
                alignItems: "center",
                gap: "0.75rem",
              }}
            >
              <div
                style={{
                  width: "36px", height: "36px", borderRadius: "8px", flexShrink: 0,
                  background: `color-mix(in srgb, ${s.color} 15%, transparent)`,
                  color: s.color,
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}
              >
                <s.icon size={17} />
              </div>
              <div>
                <div style={{ fontSize: "1.25rem", fontWeight: 700, lineHeight: 1.2, color: "var(--text)" }}>
                  {s.value}
                </div>
                <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: "1px" }}>
                  {s.label}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Future modules */}
      <div style={{ marginBottom: "1rem" }}>
        <h2 style={{ fontSize: "0.85rem", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "1rem" }}>
          Modules
        </h2>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))",
            gap: "1rem",
          }}
        >
          {futureModules.map(({ icon: Icon, label, description }) => (
            <div
              key={label}
              style={{
                padding: "1.25rem",
                borderRadius: "10px",
                border: "1px solid var(--border)",
                background: "var(--surface)",
                opacity: 0.6,
                position: "relative",
                overflow: "hidden",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.6rem" }}>
                <Icon size={16} style={{ color: "var(--text-muted)" }} />
                <span style={{ fontSize: "0.9rem", fontWeight: 600, color: "var(--text)" }}>{label}</span>
                <span
                  style={{
                    marginLeft: "auto",
                    fontSize: "0.62rem", padding: "2px 6px", borderRadius: "4px",
                    background: "var(--surface-3)", color: "var(--text-dim)",
                  }}
                >
                  coming soon
                </span>
              </div>
              <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", lineHeight: 1.5, margin: 0 }}>
                {description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
