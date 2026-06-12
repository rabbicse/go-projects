import type { Metadata } from "next";
import Link from "next/link";
import { UserBadge } from "@/components/UserBadge";
import { NavLinks } from "@/components/NavLinks";
import { QueryProvider } from "@/components/QueryProvider";
import "./globals.css";

export const metadata: Metadata = {
  title: "Cinema Booking",
  description: "Book cinema tickets instantly. Real-time seat holds, up to 4 seats per session.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <QueryProvider>
        {/* ── Nav ─────────────────────────────────────────────────────── */}
        <nav className="nav-bar">
          <div className="page-container nav-inner">
            <Link href="/" className="nav-logo">
              Cinema Booking
            </Link>
            <div className="nav-right">
              <UserBadge />
              <NavLinks />
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
        </QueryProvider>
      </body>
    </html>
  );
}
