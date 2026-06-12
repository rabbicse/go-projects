"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ChevronLeft, Plus, Loader2, CheckCircle } from "lucide-react";
import { adminHeaders } from "@/lib/adminApi";

function generateID(title: string): string {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

const inputStyle = {
  background: "var(--surface-2)",
  border: "1px solid var(--border)",
  color: "var(--text)",
  borderRadius: "8px",
  padding: "0.625rem 0.75rem",
  width: "100%",
  fontSize: "0.875rem",
  outline: "none",
};

export default function NewMoviePage() {
  const router = useRouter();
  const [step, setStep] = useState<"movie" | "showtime" | "done">("movie");
  const [createdMovieId, setCreatedMovieId] = useState("");

  // Movie form
  const [title, setTitle] = useState("");
  const [id, setId] = useState("");
  const [genre, setGenre] = useState("");
  const [rating, setRating] = useState("7.5");
  const [posterURL, setPosterURL] = useState("");
  const [description, setDescription] = useState("");
  const [duration, setDuration] = useState("120");
  const [publishNow, setPublishNow] = useState(false);
  const [movieError, setMovieError] = useState<string | null>(null);
  const [movieLoading, setMovieLoading] = useState(false);

  // Showtime form
  const [hall, setHall] = useState("Hall A");
  const [startTime, setStartTime] = useState("");
  const [endTime, setEndTime] = useState("");
  const [rows, setRows] = useState("8");
  const [seatsPerRow, setSeatsPerRow] = useState("10");
  const [priceCents, setPriceCents] = useState("1500");
  const [currency] = useState("USD");
  const [stError, setStError] = useState<string | null>(null);
  const [stLoading, setStLoading] = useState(false);

  async function createMovie(e: FormEvent) {
    e.preventDefault();
    setMovieLoading(true);
    setMovieError(null);
    try {
      const res = await fetch("/api/v1/admin/movies", {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({
          id: id || generateID(title),
          title,
          genre: genre.split(",").map((g) => g.trim()).filter(Boolean),
          rating: parseFloat(rating),
          poster_url: posterURL,
          description,
          duration_min: parseInt(duration),
          published: publishNow,
        }),
      });
      const data = await res.json() as { id?: string; message?: string };
      if (!res.ok) throw new Error(data.message ?? "Failed to create movie");
      setCreatedMovieId(data.id ?? "");
      setStep("showtime");
    } catch (e) {
      setMovieError(e instanceof Error ? e.message : "Error");
    } finally {
      setMovieLoading(false);
    }
  }

  async function createShowtime(e: FormEvent) {
    e.preventDefault();
    setStLoading(true);
    setStError(null);
    try {
      const showtimeID = `${createdMovieId}-${hall.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}`;
      const res = await fetch(`/api/v1/admin/movies/${createdMovieId}/showtimes`, {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({
          id: showtimeID,
          hall,
          start_time: new Date(startTime).toISOString(),
          end_time: new Date(endTime).toISOString(),
          rows: parseInt(rows),
          seats_per_row: parseInt(seatsPerRow),
          price_cents: parseInt(priceCents),
          currency,
        }),
      });
      const data = await res.json() as { message?: string };
      if (!res.ok) throw new Error(data.message ?? "Failed to create showtime");
      setStep("done");
    } catch (e) {
      setStError(e instanceof Error ? e.message : "Error");
    } finally {
      setStLoading(false);
    }
  }

  if (step === "done") {
    return (
      <div style={{ maxWidth: "480px", textAlign: "center", paddingTop: "3rem" }}>
        <CheckCircle size={48} style={{ color: "var(--success)", marginBottom: "1rem" }} />
        <h2 style={{ fontSize: "1.4rem", fontWeight: 700, color: "var(--text)", marginBottom: "0.5rem" }}>
          Movie Added!
        </h2>
        <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "1.5rem" }}>
          Movie and showtime created successfully.
        </p>
        <div style={{ display: "flex", justifyContent: "center", gap: "0.75rem" }}>
          <Link href={`/movies/${createdMovieId}`} style={{ padding: "0.55rem 1.1rem", borderRadius: "8px", background: "var(--accent)", color: "#fff", fontSize: "0.85rem", fontWeight: 600, textDecoration: "none" }}>
            View Movie
          </Link>
          <button onClick={() => router.push("/admin/movies")} style={{ padding: "0.55rem 1.1rem", borderRadius: "8px", background: "var(--surface-2)", color: "var(--text-muted)", border: "1px solid var(--border)", fontSize: "0.85rem", cursor: "pointer" }}>
            Back to Movies
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: "600px" }}>
      <Link href="/admin/movies" style={{ display: "inline-flex", alignItems: "center", gap: "0.35rem", fontSize: "0.83rem", color: "var(--text-muted)", textDecoration: "none", marginBottom: "1.5rem" }}>
        <ChevronLeft size={15} /> Back to Movies
      </Link>

      {/* Steps indicator */}
      <div style={{ display: "flex", alignItems: "center", gap: "1rem", marginBottom: "2rem" }}>
        {[{ label: "1. Movie details", key: "movie" }, { label: "2. Add showtime", key: "showtime" }].map((s) => (
          <div key={s.key} style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <div style={{ width: "22px", height: "22px", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "0.7rem", fontWeight: 700, background: step === s.key ? "var(--accent)" : "var(--surface-3)", color: step === s.key ? "#fff" : "var(--text-muted)" }}>
              {s.label[0]}
            </div>
            <span style={{ fontSize: "0.83rem", color: step === s.key ? "var(--text)" : "var(--text-muted)" }}>
              {s.label.slice(3)}
            </span>
          </div>
        ))}
      </div>

      {step === "movie" ? (
        <form onSubmit={createMovie} style={{ borderRadius: "12px", border: "1px solid var(--border)", padding: "1.5rem", background: "var(--surface)", display: "flex", flexDirection: "column", gap: "1rem" }}>
          <h2 style={{ fontSize: "1.1rem", fontWeight: 700, color: "var(--text)" }}>New Movie</h2>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
            <div style={{ gridColumn: "1 / -1" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Title *</label>
              <input value={title} onChange={(e) => { setTitle(e.target.value); setId(generateID(e.target.value)); }} required style={inputStyle} />
            </div>
            <div style={{ gridColumn: "1 / -1" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>ID (auto-generated)</label>
              <input value={id} onChange={(e) => setId(e.target.value)} placeholder="e.g. my-movie" style={{ ...inputStyle, fontFamily: "monospace", fontSize: "0.8rem" }} />
            </div>
            <div style={{ gridColumn: "1 / -1" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Genre * (comma separated)</label>
              <input value={genre} onChange={(e) => setGenre(e.target.value)} placeholder="Action, Drama, Sci-Fi" required style={inputStyle} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Rating (0–10) *</label>
              <input type="number" step="0.1" min="0" max="10" value={rating} onChange={(e) => setRating(e.target.value)} required style={inputStyle} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Duration (min) *</label>
              <input type="number" min="1" value={duration} onChange={(e) => setDuration(e.target.value)} required style={inputStyle} />
            </div>
            <div style={{ gridColumn: "1 / -1" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Poster URL</label>
              <input value={posterURL} onChange={(e) => setPosterURL(e.target.value)} placeholder="https://image.tmdb.org/…" style={inputStyle} />
            </div>
            <div style={{ gridColumn: "1 / -1" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Description</label>
              <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} style={{ ...inputStyle, resize: "vertical" }} />
            </div>
            <div style={{ gridColumn: "1 / -1", display: "flex", alignItems: "center", gap: "0.6rem" }}>
              <input
                type="checkbox"
                id="publish-now"
                checked={publishNow}
                onChange={(e) => setPublishNow(e.target.checked)}
                style={{ width: "15px", height: "15px", cursor: "pointer" }}
              />
              <label htmlFor="publish-now" style={{ fontSize: "0.83rem", color: "var(--text)", cursor: "pointer" }}>
                Publish immediately
              </label>
            </div>
          </div>

          {movieError && <p style={{ fontSize: "0.8rem", color: "var(--danger)" }}>{movieError}</p>}
          <button type="submit" disabled={movieLoading} style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "0.5rem", padding: "0.65rem", borderRadius: "8px", border: "none", background: movieLoading ? "var(--border)" : "var(--accent)", color: "#fff", fontSize: "0.9rem", fontWeight: 600, cursor: movieLoading ? "not-allowed" : "pointer" }}>
            {movieLoading ? <Loader2 size={15} className="animate-spin" /> : <Plus size={15} />}
            {movieLoading ? "Creating…" : "Create Movie & Continue"}
          </button>
        </form>
      ) : (
        <form onSubmit={createShowtime} style={{ borderRadius: "12px", border: "1px solid var(--border)", padding: "1.5rem", background: "var(--surface)", display: "flex", flexDirection: "column", gap: "1rem" }}>
          <h2 style={{ fontSize: "1.1rem", fontWeight: 700, color: "var(--text)" }}>Add First Showtime</h2>
          <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
            Adding showtime for <strong style={{ color: "var(--accent)" }}>{createdMovieId}</strong>. You can add more from the edit page.
          </p>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
            <div style={{ gridColumn: "1 / -1" }}>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Hall *</label>
              <input value={hall} onChange={(e) => setHall(e.target.value)} placeholder="Hall A" required style={inputStyle} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Start Time *</label>
              <input type="datetime-local" value={startTime} onChange={(e) => setStartTime(e.target.value)} required style={inputStyle} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>End Time *</label>
              <input type="datetime-local" value={endTime} onChange={(e) => setEndTime(e.target.value)} required style={inputStyle} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Rows (1–26) *</label>
              <input type="number" min="1" max="26" value={rows} onChange={(e) => setRows(e.target.value)} required style={inputStyle} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Seats/Row (1–30) *</label>
              <input type="number" min="1" max="30" value={seatsPerRow} onChange={(e) => setSeatsPerRow(e.target.value)} required style={inputStyle} />
            </div>
            <div>
              <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Price (cents) *</label>
              <input type="number" min="0" value={priceCents} onChange={(e) => setPriceCents(e.target.value)} required style={inputStyle} />
            </div>
            <div style={{ display: "flex", alignItems: "flex-end", paddingBottom: "0.25rem" }}>
              <p style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>= ${(parseInt(priceCents || "0") / 100).toFixed(2)} USD per seat</p>
            </div>
          </div>

          {stError && <p style={{ fontSize: "0.8rem", color: "var(--danger)" }}>{stError}</p>}
          <div style={{ display: "flex", gap: "0.75rem" }}>
            <button type="button" onClick={() => setStep("done")} style={{ flex: 1, padding: "0.65rem", borderRadius: "8px", background: "var(--surface-2)", color: "var(--text-muted)", border: "1px solid var(--border)", fontSize: "0.85rem", cursor: "pointer" }}>
              Skip showtime
            </button>
            <button type="submit" disabled={stLoading} style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", gap: "0.5rem", padding: "0.65rem", borderRadius: "8px", border: "none", background: stLoading ? "var(--border)" : "var(--accent)", color: "#fff", fontSize: "0.85rem", fontWeight: 600, cursor: stLoading ? "not-allowed" : "pointer" }}>
              {stLoading ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              Add Showtime
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
