"use client";

import { useState, FormEvent } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ChevronLeft, Plus, Loader2, CheckCircle } from "lucide-react";

function authHeaders(): HeadersInit {
  return {
    "Content-Type": "application/json",
    Authorization: "Basic " + btoa("admin:admin"),
  };
}

function generateID(title: string): string {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

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
        headers: authHeaders(),
        body: JSON.stringify({
          id: id || generateID(title),
          title,
          genre: genre.split(",").map((g) => g.trim()).filter(Boolean),
          rating: parseFloat(rating),
          poster_url: posterURL,
          description,
          duration_min: parseInt(duration),
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Failed to create movie");
      setCreatedMovieId(data.id);
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
        headers: authHeaders(),
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
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Failed to create showtime");
      setStep("done");
    } catch (e) {
      setStError(e instanceof Error ? e.message : "Error");
    } finally {
      setStLoading(false);
    }
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

  if (step === "done") {
    return (
      <div className="page-container" style={{ maxWidth: "480px", textAlign: "center", paddingTop: "5rem", paddingBottom: "4rem" }}>
        <CheckCircle size={48} className="mx-auto mb-4" style={{ color: "var(--success)" }} />
        <h2 className="text-2xl font-bold mb-2" style={{ color: "var(--text)" }}>Movie Added!</h2>
        <p className="text-sm mb-6" style={{ color: "var(--text-muted)" }}>
          Movie and showtime created successfully.
        </p>
        <div className="flex justify-center gap-3">
          <Link href={`/movies/${createdMovieId}`} className="px-4 py-2 rounded-xl text-sm font-semibold no-underline" style={{ background: "var(--accent)", color: "#fff" }}>
            View Movie
          </Link>
          <Link href="/admin" className="px-4 py-2 rounded-xl text-sm font-semibold no-underline" style={{ background: "var(--surface-2)", color: "var(--text-muted)", border: "1px solid var(--border)" }}>
            Back to Admin
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="page-container" style={{ maxWidth: "600px", paddingTop: "2.5rem", paddingBottom: "4rem" }}>
      <Link href="/admin" className="inline-flex items-center gap-1.5 text-sm mb-6 no-underline" style={{ color: "var(--text-muted)" }}>
        <ChevronLeft size={16} /> Back to Admin
      </Link>

      {/* Steps indicator */}
      <div className="flex items-center gap-3 mb-8">
        {[{ label: "1. Movie details", key: "movie" }, { label: "2. Add showtime", key: "showtime" }].map((s) => (
          <div key={s.key} className="flex items-center gap-2">
            <div
              className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold"
              style={{
                background: step === s.key ? "var(--accent)" : "var(--surface-3)",
                color: step === s.key ? "#fff" : "var(--text-muted)",
              }}
            >
              {s.label[0]}
            </div>
            <span className="text-sm" style={{ color: step === s.key ? "var(--text)" : "var(--text-muted)" }}>
              {s.label.slice(3)}
            </span>
          </div>
        ))}
      </div>

      {step === "movie" ? (
        <form onSubmit={createMovie} className="rounded-2xl border p-6 space-y-4" style={{ background: "var(--surface)", borderColor: "var(--border)" }}>
          <h2 className="text-xl font-bold mb-2" style={{ color: "var(--text)" }}>New Movie</h2>

          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Title *</label>
              <input value={title} onChange={(e) => { setTitle(e.target.value); setId(generateID(e.target.value)); }} required style={inputStyle} />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>ID (auto-generated)</label>
              <input value={id} onChange={(e) => setId(e.target.value)} placeholder="e.g. my-movie" style={{ ...inputStyle, fontFamily: "monospace", fontSize: "0.8rem" }} />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Genre * (comma separated)</label>
              <input value={genre} onChange={(e) => setGenre(e.target.value)} placeholder="Action, Drama, Sci-Fi" required style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Rating (0–10) *</label>
              <input type="number" step="0.1" min="0" max="10" value={rating} onChange={(e) => setRating(e.target.value)} required style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Duration (min) *</label>
              <input type="number" min="1" value={duration} onChange={(e) => setDuration(e.target.value)} required style={inputStyle} />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Poster URL</label>
              <input value={posterURL} onChange={(e) => setPosterURL(e.target.value)} placeholder="https://image.tmdb.org/…" style={inputStyle} />
            </div>
            <div className="col-span-2">
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Description</label>
              <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} style={{ ...inputStyle, resize: "vertical" }} />
            </div>
          </div>

          {movieError && <p className="text-xs" style={{ color: "var(--danger)" }}>{movieError}</p>}
          <button type="submit" disabled={movieLoading} className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold disabled:opacity-60" style={{ background: "var(--accent)", color: "#fff" }}>
            {movieLoading ? <Loader2 size={16} className="animate-spin" /> : <Plus size={16} />}
            {movieLoading ? "Creating…" : "Create Movie & Continue"}
          </button>
        </form>
      ) : (
        <form onSubmit={createShowtime} className="rounded-2xl border p-6 space-y-4" style={{ background: "var(--surface)", borderColor: "var(--border)" }}>
          <h2 className="text-xl font-bold mb-2" style={{ color: "var(--text)" }}>Add First Showtime</h2>
          <p className="text-xs mb-4" style={{ color: "var(--text-muted)" }}>
            Adding showtime for <strong style={{ color: "var(--accent)" }}>{createdMovieId}</strong>. You can add more later via API.
          </p>

          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Hall *</label>
              <input value={hall} onChange={(e) => setHall(e.target.value)} placeholder="Hall A" required style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Start Time *</label>
              <input type="datetime-local" value={startTime} onChange={(e) => setStartTime(e.target.value)} required style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>End Time *</label>
              <input type="datetime-local" value={endTime} onChange={(e) => setEndTime(e.target.value)} required style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Rows (1–26) *</label>
              <input type="number" min="1" max="26" value={rows} onChange={(e) => setRows(e.target.value)} required style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Seats/Row (1–30) *</label>
              <input type="number" min="1" max="30" value={seatsPerRow} onChange={(e) => setSeatsPerRow(e.target.value)} required style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: "var(--text-muted)" }}>Price (cents) *</label>
              <input type="number" min="0" value={priceCents} onChange={(e) => setPriceCents(e.target.value)} required style={inputStyle} />
            </div>
            <div className="flex items-end pb-0.5">
              <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                = ${(parseInt(priceCents || "0") / 100).toFixed(2)} USD per seat
              </p>
            </div>
          </div>

          {stError && <p className="text-xs" style={{ color: "var(--danger)" }}>{stError}</p>}
          <div className="flex gap-3">
            <button type="button" onClick={() => setStep("done")} className="flex-1 py-2.5 rounded-xl text-sm font-semibold" style={{ background: "var(--surface-2)", color: "var(--text-muted)", border: "1px solid var(--border)" }}>
              Skip showtime
            </button>
            <button type="submit" disabled={stLoading} className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-semibold disabled:opacity-60" style={{ background: "var(--accent)", color: "#fff" }}>
              {stLoading ? <Loader2 size={16} className="animate-spin" /> : <Plus size={16} />}
              Add Showtime
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
