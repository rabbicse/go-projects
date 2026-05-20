import type { Metadata } from "next";
import Link from "next/link";
import { UserBadge } from "@/components/UserBadge";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cinema Booking",
  description: "Book cinema tickets instantly. Real-time seat holds, up to 4 seats per session.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        {/* ── Nav ─────────────────────────────────────────────────────── */}
        <nav className="nav-bar">
          <div className="page-container nav-inner">
            <Link href="/" className="nav-logo">
              Cinema Booking
            </Link>
            <div className="nav-right">
              <UserBadge />
              <Link href="/api/v1/docs" target="_blank" rel="noopener noreferrer" className="nav-link">
                API Docs ↗
              </Link>
              <Link href="/admin" className="nav-link">
                Admin
              </Link>
            </div>
          </div>
        </nav>

        {/* ── Content (NO container — each page owns its layout) ─────── */}
        <main>{children}</main>

        {/* ── Footer ──────────────────────────────────────────────────── */}
        <footer className="footer">
          <div className="page-container footer-inner">
            Cinema Booking &mdash; Up to 4 seats per session &bull; Holds expire in 10 min
          </div>
        </footer>
      </body>
    </html>
  );
}
