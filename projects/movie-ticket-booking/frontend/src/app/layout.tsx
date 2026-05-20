import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "CineBook — Movie Ticket Booking",
  description: "Book cinema tickets instantly. Atomic multi-seat holds, real-time availability.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        {/* Navigation */}
        <nav
          className="sticky top-0 z-50 border-b"
          style={{
            background: "rgba(8, 8, 15, 0.85)",
            borderColor: "var(--border)",
            backdropFilter: "blur(16px)",
            WebkitBackdropFilter: "blur(16px)",
          }}
        >
          <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
            {/* Logo */}
            <Link href="/" className="flex items-center gap-3 no-underline">
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center text-sm font-bold"
                style={{ background: "var(--accent)", color: "#fff" }}
              >
                C
              </div>
              <span className="font-bold text-lg tracking-tight" style={{ color: "var(--text)" }}>
                CineBook
              </span>
            </Link>

            {/* Right side */}
            <div className="flex items-center gap-3">
              <Link
                href="/api/v1/docs"
                target="_blank"
                rel="noopener noreferrer"
                className="hidden sm:flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg no-underline transition-colors"
                style={{
                  color: "var(--text-muted)",
                  border: "1px solid var(--border)",
                  background: "var(--surface)",
                }}
              >
                <span>API Docs</span>
                <span style={{ color: "var(--text-dim)" }}>↗</span>
              </Link>
              <Link
                href="/admin"
                className="text-xs px-3 py-1.5 rounded-lg no-underline font-medium transition-colors"
                style={{
                  background: "var(--surface-2)",
                  color: "var(--text-muted)",
                  border: "1px solid var(--border)",
                }}
              >
                Admin
              </Link>
            </div>
          </div>
        </nav>

        {/* Page content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 py-8">{children}</main>

        {/* Footer */}
        <footer
          className="mt-20 border-t py-8 text-center text-xs"
          style={{ borderColor: "var(--border)", color: "var(--text-dim)" }}
        >
          <p>CineBook — Up to 4 seats per session &bull; Holds expire in 10 minutes</p>
        </footer>
      </body>
    </html>
  );
}
