"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { LayoutDashboard, Film, Building2, CalendarDays, DollarSign, BarChart3, LogOut } from "lucide-react";
import { isAuthenticated, hasRole, logout } from "@/lib/auth";

type GuardState = "loading" | "ok" | "forbidden";

const navItems = [
  { label: "Dashboard", href: "/admin/dashboard", icon: LayoutDashboard, available: true },
  { label: "Movies", href: "/admin/movies", icon: Film, available: true },
  { label: "Theaters", href: "/admin/theaters", icon: Building2, available: true },
  { label: "Shows", href: "/admin/shows", icon: CalendarDays, available: true },
  { label: "Pricing", href: "/admin/pricing", icon: DollarSign, available: false },
  { label: "Analytics", href: "/admin/analytics", icon: BarChart3, available: false },
];

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [guard, setGuard] = useState<GuardState>("loading");

  useEffect(() => {
    if (!isAuthenticated()) {
      router.replace("/login");
    } else if (!hasRole("admin")) {
      setGuard("forbidden");
    } else {
      setGuard("ok");
    }
  }, [router]);

  if (guard === "loading") return null;

  if (guard === "forbidden") {
    return (
      <div
        className="page-container"
        style={{ paddingTop: "5rem", maxWidth: "420px", textAlign: "center" }}
      >
        <div
          style={{
            fontSize: "3rem", fontWeight: 800, color: "var(--danger)",
            lineHeight: 1, marginBottom: "0.5rem",
          }}
        >
          403
        </div>
        <h1 style={{ fontSize: "1.2rem", fontWeight: 700, marginBottom: "0.5rem" }}>
          Access denied
        </h1>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "1.5rem" }}>
          Your account does not have the <code>admin</code> role.
        </p>
        <Link
          href="/"
          style={{
            padding: "0.55rem 1.2rem", borderRadius: "7px",
            background: "var(--accent)", color: "#fff",
            fontSize: "0.85rem", textDecoration: "none",
          }}
        >
          Go home
        </Link>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", minHeight: `calc(100vh - var(--nav-h))` }}>
      {/* ── Sidebar ── */}
      <aside
        style={{
          width: "220px",
          flexShrink: 0,
          borderRight: "1px solid var(--border)",
          background: "var(--surface)",
          padding: "1.5rem 0",
          display: "flex",
          flexDirection: "column",
        }}
      >
        {/* Branding */}
        <div
          style={{
            padding: "0 1.25rem",
            marginBottom: "1.5rem",
            display: "flex",
            alignItems: "center",
            gap: "0.6rem",
          }}
        >
          <div
            style={{
              width: "28px", height: "28px", borderRadius: "6px",
              background: "var(--accent)", color: "#fff",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: "0.7rem", fontWeight: 800,
            }}
          >
            A
          </div>
          <span style={{ fontSize: "0.82rem", fontWeight: 600, color: "var(--text)" }}>
            Admin Panel
          </span>
        </div>

        {/* Nav items */}
        <nav style={{ flex: 1, padding: "0 0.75rem", display: "flex", flexDirection: "column", gap: "2px" }}>
          {navItems.map(({ label, href, icon: Icon, available }) => {
            const active = pathname === href || pathname.startsWith(href + "/");
            return available ? (
              <Link
                key={href}
                href={href}
                style={{
                  display: "flex", alignItems: "center", gap: "0.6rem",
                  padding: "0.5rem 0.75rem", borderRadius: "7px",
                  fontSize: "0.83rem", fontWeight: active ? 600 : 400,
                  color: active ? "var(--accent)" : "var(--text-muted)",
                  background: active ? "var(--accent-glow)" : "transparent",
                  textDecoration: "none", transition: "background 0.12s, color 0.12s",
                }}
              >
                <Icon size={15} />
                {label}
              </Link>
            ) : (
              <div
                key={href}
                style={{
                  display: "flex", alignItems: "center", justifyContent: "space-between",
                  padding: "0.5rem 0.75rem", borderRadius: "7px",
                  fontSize: "0.83rem", color: "var(--text-dim)", cursor: "default",
                }}
              >
                <span style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                  <Icon size={15} />
                  {label}
                </span>
                <span
                  style={{
                    fontSize: "0.62rem", padding: "1px 5px", borderRadius: "4px",
                    background: "var(--surface-2)", color: "var(--text-dim)",
                    letterSpacing: "0.03em",
                  }}
                >
                  soon
                </span>
              </div>
            );
          })}
        </nav>

        {/* Sign out */}
        <div style={{ padding: "0 0.75rem", marginTop: "auto", paddingTop: "1rem" }}>
          <button
            onClick={() => void logout()}
            style={{
              width: "100%", display: "flex", alignItems: "center", gap: "0.6rem",
              padding: "0.5rem 0.75rem", borderRadius: "7px",
              fontSize: "0.83rem", color: "var(--text-muted)",
              background: "transparent", border: "none", cursor: "pointer",
              transition: "background 0.12s",
            }}
          >
            <LogOut size={14} />
            Sign out
          </button>
        </div>
      </aside>

      {/* ── Main content ── */}
      <main style={{ flex: 1, padding: "2rem 2.5rem", overflowY: "auto" }}>
        {children}
      </main>
    </div>
  );
}
