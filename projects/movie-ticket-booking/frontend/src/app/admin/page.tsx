"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import Image from "next/image";
import { useRouter } from "next/navigation";
import { Plus, LogOut, Film, Clock, Ticket, RefreshCw, Loader2 } from "lucide-react";
import type { Movie } from "@/types";

const ADMIN_KEY = "cinebook_admin";

function authHeaders(): HeadersInit {
  return {
    "Content-Type": "application/json",
    Authorization: "Basic " + btoa("admin:admin"),
  };
}

export default function AdminPage() {
  const router = useRouter();
  const [movies, setMovies] = useState<Movie[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window !== "undefined" && !sessionStorage.getItem(ADMIN_KEY)) {
      router.replace("/admin/login");
    }
  }, [router]);

  const fetchMovies = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/v1/admin/movies", { headers: authHeaders() });
      if (res.status === 401) { router.replace("/admin/login"); return; }
      if (!res.ok) throw new Error("Failed to load movies");
      setMovies(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => { fetchMovies(); }, [fetchMovies]);

  function logout() {
    sessionStorage.removeItem(ADMIN_KEY);
    router.push("/");
  }

  const totalShowtimes = movies.reduce((acc, m) => acc + (m.showtimes?.length ?? 0), 0);
  const totalSeats = movies.reduce(
    (acc, m) => acc + (m.showtimes?.reduce((a, s) => a + s.total_seats, 0) ?? 0), 0
  );

  return (
    <div className="page-container" style={{ paddingTop: "2.5rem", paddingBottom: "4rem" }}>
      {/* Header */}
      <div className="flex items-start justify-between mb-8 gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div
              className="w-7 h-7 rounded-md flex items-center justify-center text-xs font-bold"
              style={{ background: "var(--accent)", color: "#fff" }}
            >
              A
            </div>
            <span className="text-xs font-medium" style={{ color: "var(--text-muted)" }}>
              Admin Panel
            </span>
          </div>
          <h1 className="text-2xl font-bold" style={{ color: "var(--text)" }}>
            Movie Management
          </h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchMovies}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm transition-colors"
            style={{ background: "var(--surface-2)", color: "var(--text-muted)", border: "1px solid var(--border)" }}
          >
            <RefreshCw size={14} />
            Refresh
          </button>
          <Link
            href="/admin/movies/new"
            className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-semibold no-underline transition-colors"
            style={{ background: "var(--accent)", color: "#fff" }}
          >
            <Plus size={15} />
            Add Movie
          </Link>
          <button
            onClick={logout}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-sm transition-colors"
            style={{ background: "var(--surface)", color: "var(--text-muted)", border: "1px solid var(--border)" }}
          >
            <LogOut size={14} />
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-8">
        {[
          { label: "Total Movies", value: movies.length, icon: Film, color: "var(--accent)" },
          { label: "Total Showtimes", value: totalShowtimes, icon: Clock, color: "var(--warning)" },
          { label: "Total Seats", value: totalSeats.toLocaleString(), icon: Ticket, color: "var(--success)" },
        ].map((s) => (
          <div
            key={s.label}
            className="rounded-xl border p-5 flex items-center gap-4"
            style={{ background: "var(--surface)", borderColor: "var(--border)" }}
          >
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center"
              style={{ background: `${s.color}20`, color: s.color }}
            >
              <s.icon size={20} />
            </div>
            <div>
              <div className="text-2xl font-bold" style={{ color: "var(--text)" }}>{s.value}</div>
              <div className="text-xs" style={{ color: "var(--text-muted)" }}>{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Movie table */}
      {loading ? (
        <div className="flex items-center justify-center py-20" style={{ color: "var(--text-muted)" }}>
          <Loader2 size={24} className="animate-spin mr-2" /> Loading movies…
        </div>
      ) : error ? (
        <div className="text-center py-16 rounded-xl border" style={{ background: "var(--surface)", borderColor: "var(--danger)", color: "var(--danger)" }}>
          {error} — is the backend running?
        </div>
      ) : movies.length === 0 ? (
        <div className="text-center py-20 rounded-xl border" style={{ background: "var(--surface)", borderColor: "var(--border)", color: "var(--text-muted)" }}>
          <Film size={40} className="mx-auto mb-3 opacity-40" />
          <p>No movies yet.</p>
          <Link href="/admin/movies/new" className="mt-3 inline-flex items-center gap-1.5 text-sm no-underline" style={{ color: "var(--accent)" }}>
            <Plus size={14} /> Add your first movie
          </Link>
        </div>
      ) : (
        <div
          className="rounded-xl border overflow-hidden"
          style={{ background: "var(--surface)", borderColor: "var(--border)" }}
        >
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)", background: "var(--surface-2)" }}>
                {["Movie", "Genre", "Rating", "Duration", "Showtimes", "Actions"].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider"
                    style={{ color: "var(--text-muted)" }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {movies.map((m, i) => (
                <tr
                  key={m.id}
                  style={{ borderBottom: i < movies.length - 1 ? "1px solid var(--border)" : "none" }}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <div
                        className="relative w-9 h-12 rounded-md overflow-hidden shrink-0"
                        style={{ background: "var(--surface-3)" }}
                      >
                        {m.poster_url && (
                          <Image src={m.poster_url} alt={m.title} fill className="object-cover" sizes="36px" />
                        )}
                      </div>
                      <div>
                        <div className="font-medium" style={{ color: "var(--text)" }}>{m.title}</div>
                        <div className="text-xs" style={{ color: "var(--text-dim)" }}>{m.id}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {m.genre.slice(0, 2).map((g) => (
                        <span
                          key={g}
                          className="text-xs px-1.5 py-0.5 rounded"
                          style={{ background: "var(--surface-3)", color: "var(--text-muted)" }}
                        >
                          {g}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-semibold" style={{ color: "var(--warning)" }}>
                    {m.rating.toFixed(1)}
                  </td>
                  <td className="px-4 py-3" style={{ color: "var(--text-muted)" }}>
                    {m.duration_min}m
                  </td>
                  <td className="px-4 py-3" style={{ color: "var(--text)" }}>
                    {m.showtimes?.length ?? 0}
                  </td>
                  <td className="px-4 py-3">
                    <Link
                      href={`/movies/${m.id}`}
                      className="text-xs no-underline px-2 py-1 rounded"
                      style={{ color: "var(--accent)", background: "var(--accent-glow)" }}
                    >
                      View →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
