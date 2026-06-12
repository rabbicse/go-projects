"use client";

import { useEffect, useRef, useState, FormEvent } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ChevronLeft, Save, Trash2, Plus, Loader2, Eye, EyeOff, Upload } from "lucide-react";
import { adminHeaders } from "@/lib/adminApi";
import type { Movie, Showtime } from "@/types";

const inputStyle: React.CSSProperties = {
  background: "var(--surface-2)",
  border: "1px solid var(--border)",
  color: "var(--text)",
  borderRadius: "8px",
  padding: "0.625rem 0.75rem",
  width: "100%",
  fontSize: "0.875rem",
  outline: "none",
};

export default function MovieDetailPage() {
  const router = useRouter();
  const { movieId } = useParams<{ movieId: string }>();

  const [movie, setMovie] = useState<Movie | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [title, setTitle] = useState("");
  const [genre, setGenre] = useState("");
  const [rating, setRating] = useState("7.5");
  const [posterURL, setPosterURL] = useState("");
  const [description, setDescription] = useState("");
  const [duration, setDuration] = useState("120");
  const [published, setPublished] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  // Poster upload
  const posterInputRef = useRef<HTMLInputElement>(null);
  const [posterUploading, setPosterUploading] = useState(false);
  const [posterError, setPosterError] = useState<string | null>(null);

  // Publish toggle
  const [publishing, setPublishing] = useState(false);
  const [publishError, setPublishError] = useState<string | null>(null);

  const [showStForm, setShowStForm] = useState(false);
  const [stHall, setStHall] = useState("Hall A");
  const [stStart, setStStart] = useState("");
  const [stEnd, setStEnd] = useState("");
  const [stRows, setStRows] = useState("8");
  const [stSeats, setStSeats] = useState("10");
  const [stPrice, setStPrice] = useState("1500");
  const [stLoading, setStLoading] = useState(false);
  const [stError, setStError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/v1/movies/${movieId}`)
      .then((r) => r.json())
      .then((m: Movie) => {
        setMovie(m);
        setTitle(m.title);
        setGenre(m.genre.join(", "));
        setRating(String(m.rating));
        setPosterURL(m.poster_url ?? "");
        setDescription(m.description ?? "");
        setDuration(String(m.duration_min));
        setPublished(m.published ?? false);
      })
      .catch(() => setError("Failed to load movie"))
      .finally(() => setLoading(false));
  }, [movieId]);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    setSaveError(null);
    setSaved(false);
    try {
      const res = await fetch(`/api/v1/admin/movies/${movieId}`, {
        method: "PUT",
        headers: adminHeaders(),
        body: JSON.stringify({
          title,
          genre: genre.split(",").map((g) => g.trim()).filter(Boolean),
          rating: parseFloat(rating),
          poster_url: posterURL,
          description,
          duration_min: parseInt(duration),
        }),
      });
      const data = await res.json() as Movie & { message?: string };
      if (!res.ok) throw new Error(data.message ?? "Save failed");
      setMovie(data);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Error");
    } finally {
      setSaving(false);
    }
  }

  async function handleTogglePublish() {
    setPublishing(true);
    setPublishError(null);
    try {
      const action = published ? "unpublish" : "publish";
      const res = await fetch(`/api/v1/admin/movies/${movieId}/${action}`, {
        method: "PUT",
        headers: adminHeaders(),
      });
      const data = await res.json() as Movie & { message?: string };
      if (!res.ok) throw new Error(data.message ?? `${action} failed`);
      setPublished(data.published);
      setMovie((prev) => prev ? { ...prev, published: data.published } : prev);
    } catch (e) {
      setPublishError(e instanceof Error ? e.message : "Error");
    } finally {
      setPublishing(false);
    }
  }

  async function handleUploadPoster(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setPosterUploading(true);
    setPosterError(null);
    try {
      const form = new FormData();
      form.append("poster", file);
      // Do NOT set Content-Type — browser must set it with the multipart boundary.
      const { "Content-Type": _ct, ...uploadHeaders } = adminHeaders();
      const res = await fetch(`/api/v1/admin/movies/${movieId}/poster`, {
        method: "POST",
        headers: uploadHeaders,
        body: form,
      });
      const data = await res.json() as { poster_url?: string; message?: string };
      if (!res.ok) throw new Error(data.message ?? "Upload failed");
      if (data.poster_url) {
        setPosterURL(data.poster_url);
        setMovie((prev) => prev ? { ...prev, poster_url: data.poster_url! } : prev);
      }
    } catch (e) {
      setPosterError(e instanceof Error ? e.message : "Upload error");
    } finally {
      setPosterUploading(false);
      if (posterInputRef.current) posterInputRef.current.value = "";
    }
  }

  async function handleDeleteMovie() {
    if (!confirm(`Permanently delete "${title}"? All showtimes will also be removed.`)) return;
    const res = await fetch(`/api/v1/admin/movies/${movieId}`, {
      method: "DELETE",
      headers: adminHeaders(),
    });
    if (res.ok) router.push("/admin/movies");
    else alert("Delete failed");
  }

  async function handleDeleteShowtime(st: Showtime) {
    if (!confirm(`Delete showtime at ${st.hall}?`)) return;
    const res = await fetch(`/api/v1/admin/movies/${movieId}/showtimes/${st.id}`, {
      method: "DELETE",
      headers: adminHeaders(),
    });
    if (res.ok) {
      setMovie((prev) =>
        prev ? { ...prev, showtimes: prev.showtimes.filter((s) => s.id !== st.id) } : prev
      );
    } else {
      alert("Delete showtime failed");
    }
  }

  async function handleAddShowtime(e: FormEvent) {
    e.preventDefault();
    setStLoading(true);
    setStError(null);
    try {
      const stID = `${movieId}-${stHall.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}`;
      const res = await fetch(`/api/v1/admin/movies/${movieId}/showtimes`, {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({
          id: stID,
          hall: stHall,
          start_time: new Date(stStart).toISOString(),
          end_time: new Date(stEnd).toISOString(),
          rows: parseInt(stRows),
          seats_per_row: parseInt(stSeats),
          price_cents: parseInt(stPrice),
          currency: "USD",
        }),
      });
      const data = await res.json() as Showtime & { message?: string };
      if (!res.ok) throw new Error(data.message ?? "Failed");
      setMovie((prev) =>
        prev ? { ...prev, showtimes: [...(prev.showtimes ?? []), data] } : prev
      );
      setShowStForm(false);
      setStHall("Hall A"); setStStart(""); setStEnd("");
    } catch (e) {
      setStError(e instanceof Error ? e.message : "Error");
    } finally {
      setStLoading(false);
    }
  }

  if (loading) return (
    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", padding: "4rem 0", color: "var(--text-muted)" }}>
      <Loader2 size={20} className="animate-spin" /> Loading…
    </div>
  );

  if (error || !movie) return (
    <div style={{ padding: "4rem 0", color: "var(--danger)" }}>
      {error ?? "Movie not found"}{" "}
      <Link href="/admin/movies" style={{ color: "var(--accent)" }}>← Movies</Link>
    </div>
  );

  return (
    <div style={{ maxWidth: "720px" }}>
      <Link href="/admin/movies" style={{ display: "inline-flex", alignItems: "center", gap: "0.35rem", fontSize: "0.83rem", color: "var(--text-muted)", textDecoration: "none", marginBottom: "1.5rem" }}>
        <ChevronLeft size={15} /> Back to Movies
      </Link>

      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "1.5rem", gap: "1rem", flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <h1 style={{ fontSize: "1.25rem", fontWeight: 700, color: "var(--text)" }}>{title}</h1>
          <span
            style={{
              display: "inline-block", padding: "2px 8px", borderRadius: "12px",
              fontSize: "0.72rem", fontWeight: 600,
              background: published
                ? "color-mix(in srgb, var(--success) 15%, transparent)"
                : "var(--surface-2)",
              color: published ? "var(--success)" : "var(--text-muted)",
              border: published
                ? "1px solid color-mix(in srgb, var(--success) 30%, transparent)"
                : "1px solid var(--border)",
            }}
          >
            {published ? "Published" : "Draft"}
          </span>
        </div>
        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button
            onClick={handleTogglePublish}
            disabled={publishing}
            style={{
              display: "inline-flex", alignItems: "center", gap: "0.4rem",
              padding: "0.45rem 0.9rem", borderRadius: "7px", fontSize: "0.82rem",
              color: published ? "var(--text-muted)" : "var(--success)",
              background: published ? "var(--surface-2)" : "color-mix(in srgb, var(--success) 12%, transparent)",
              border: "1px solid var(--border)", cursor: publishing ? "not-allowed" : "pointer",
            }}
          >
            {publishing ? <Loader2 size={13} className="animate-spin" /> : published ? <EyeOff size={13} /> : <Eye size={13} />}
            {published ? "Unpublish" : "Publish"}
          </button>
          <button onClick={handleDeleteMovie} style={{ display: "inline-flex", alignItems: "center", gap: "0.4rem", padding: "0.45rem 0.9rem", borderRadius: "7px", fontSize: "0.82rem", color: "var(--danger)", background: "color-mix(in srgb, var(--danger) 12%, transparent)", border: "1px solid var(--danger)", cursor: "pointer" }}>
            <Trash2 size={13} /> Delete Movie
          </button>
        </div>
      </div>
      {publishError && (
        <div style={{ marginBottom: "1rem", padding: "0.6rem 0.9rem", borderRadius: "7px", border: "1px solid var(--danger)", background: "color-mix(in srgb, var(--danger) 10%, transparent)", fontSize: "0.8rem", color: "var(--danger)" }}>
          {publishError}
        </div>
      )}

      {/* Edit form */}
      <form onSubmit={handleSave} style={{ borderRadius: "12px", border: "1px solid var(--border)", padding: "1.5rem", background: "var(--surface)", display: "flex", flexDirection: "column", gap: "1rem", marginBottom: "1.5rem" }}>
        <h2 style={{ fontSize: "0.95rem", fontWeight: 600, color: "var(--text)" }}>Movie Details</h2>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
          <div style={{ gridColumn: "1 / -1" }}>
            <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Title *</label>
            <input value={title} onChange={(e) => setTitle(e.target.value)} required style={inputStyle} />
          </div>
          <div style={{ gridColumn: "1 / -1" }}>
            <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Genre (comma separated) *</label>
            <input value={genre} onChange={(e) => setGenre(e.target.value)} required style={inputStyle} />
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
            <input value={posterURL} onChange={(e) => setPosterURL(e.target.value)} placeholder="https://…" style={inputStyle} />
          </div>
          <div style={{ gridColumn: "1 / -1" }}>
            <label style={{ display: "block", fontSize: "0.75rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.4rem" }}>Description</label>
            <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3} style={{ ...inputStyle, resize: "vertical" }} />
          </div>
        </div>

        {saveError && <p style={{ fontSize: "0.8rem", color: "var(--danger)" }}>{saveError}</p>}
        <button type="submit" disabled={saving} style={{ display: "inline-flex", alignItems: "center", gap: "0.4rem", padding: "0.55rem 1.1rem", borderRadius: "8px", border: "none", background: saved ? "var(--success)" : "var(--accent)", color: "#fff", fontSize: "0.85rem", fontWeight: 600, cursor: saving ? "not-allowed" : "pointer" }}>
          {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
          {saving ? "Saving…" : saved ? "Saved!" : "Save Changes"}
        </button>
      </form>

      {/* Poster upload */}
      <div style={{ borderRadius: "12px", border: "1px solid var(--border)", padding: "1.5rem", background: "var(--surface)", marginBottom: "1.5rem" }}>
        <h2 style={{ fontSize: "0.95rem", fontWeight: 600, color: "var(--text)", marginBottom: "1rem" }}>Poster</h2>
        <div style={{ display: "flex", alignItems: "center", gap: "1rem", flexWrap: "wrap" }}>
          {posterURL && (
            <img
              src={posterURL}
              alt="Poster preview"
              style={{ width: "60px", height: "80px", objectFit: "cover", borderRadius: "6px", border: "1px solid var(--border)" }}
            />
          )}
          <div style={{ flex: 1, minWidth: "200px" }}>
            <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.5rem" }}>
              Upload a new poster (jpg, png, webp — max 4 MB). Or enter a URL in the form above.
            </p>
            <input
              ref={posterInputRef}
              type="file"
              accept=".jpg,.jpeg,.png,.webp"
              style={{ display: "none" }}
              onChange={handleUploadPoster}
            />
            <button
              type="button"
              onClick={() => posterInputRef.current?.click()}
              disabled={posterUploading}
              style={{
                display: "inline-flex", alignItems: "center", gap: "0.4rem",
                padding: "0.45rem 0.9rem", borderRadius: "7px", fontSize: "0.82rem",
                background: "var(--surface-2)", color: "var(--text)",
                border: "1px solid var(--border)", cursor: posterUploading ? "not-allowed" : "pointer",
              }}
            >
              {posterUploading ? <Loader2 size={13} className="animate-spin" /> : <Upload size={13} />}
              {posterUploading ? "Uploading…" : "Upload poster"}
            </button>
            {posterError && <p style={{ fontSize: "0.78rem", color: "var(--danger)", marginTop: "0.4rem" }}>{posterError}</p>}
          </div>
        </div>
      </div>

      {/* Showtimes */}
      <div style={{ borderRadius: "12px", border: "1px solid var(--border)", padding: "1.5rem", background: "var(--surface)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1rem" }}>
          <h2 style={{ fontSize: "0.95rem", fontWeight: 600, color: "var(--text)" }}>
            Showtimes ({movie.showtimes?.length ?? 0})
          </h2>
          <button onClick={() => setShowStForm((v) => !v)} style={{ display: "inline-flex", alignItems: "center", gap: "0.3rem", padding: "0.35rem 0.75rem", borderRadius: "6px", fontSize: "0.78rem", fontWeight: 600, background: "var(--accent)", color: "#fff", border: "none", cursor: "pointer" }}>
            <Plus size={12} /> Add Showtime
          </button>
        </div>

        {showStForm && (
          <form onSubmit={handleAddShowtime} style={{ borderRadius: "8px", border: "1px solid var(--border)", padding: "1rem", marginBottom: "1rem", background: "var(--surface-2)", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
              <div style={{ gridColumn: "1 / -1" }}>
                <label style={{ display: "block", fontSize: "0.72rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.3rem" }}>Hall *</label>
                <input value={stHall} onChange={(e) => setStHall(e.target.value)} required style={{ ...inputStyle, padding: "0.5rem 0.6rem" }} />
              </div>
              <div>
                <label style={{ display: "block", fontSize: "0.72rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.3rem" }}>Start *</label>
                <input type="datetime-local" value={stStart} onChange={(e) => setStStart(e.target.value)} required style={{ ...inputStyle, padding: "0.5rem 0.6rem" }} />
              </div>
              <div>
                <label style={{ display: "block", fontSize: "0.72rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.3rem" }}>End *</label>
                <input type="datetime-local" value={stEnd} onChange={(e) => setStEnd(e.target.value)} required style={{ ...inputStyle, padding: "0.5rem 0.6rem" }} />
              </div>
              <div>
                <label style={{ display: "block", fontSize: "0.72rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.3rem" }}>Rows *</label>
                <input type="number" min="1" max="26" value={stRows} onChange={(e) => setStRows(e.target.value)} required style={{ ...inputStyle, padding: "0.5rem 0.6rem" }} />
              </div>
              <div>
                <label style={{ display: "block", fontSize: "0.72rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.3rem" }}>Seats/Row *</label>
                <input type="number" min="1" max="30" value={stSeats} onChange={(e) => setStSeats(e.target.value)} required style={{ ...inputStyle, padding: "0.5rem 0.6rem" }} />
              </div>
              <div>
                <label style={{ display: "block", fontSize: "0.72rem", fontWeight: 500, color: "var(--text-muted)", marginBottom: "0.3rem" }}>Price (cents) *</label>
                <input type="number" min="0" value={stPrice} onChange={(e) => setStPrice(e.target.value)} required style={{ ...inputStyle, padding: "0.5rem 0.6rem" }} />
              </div>
              <div style={{ display: "flex", alignItems: "flex-end" }}>
                <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>= ${(parseInt(stPrice || "0") / 100).toFixed(2)} USD</span>
              </div>
            </div>
            {stError && <p style={{ fontSize: "0.78rem", color: "var(--danger)" }}>{stError}</p>}
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button type="submit" disabled={stLoading} style={{ display: "inline-flex", alignItems: "center", gap: "0.3rem", padding: "0.45rem 0.85rem", borderRadius: "6px", fontSize: "0.78rem", fontWeight: 600, background: "var(--accent)", color: "#fff", border: "none", cursor: "pointer" }}>
                {stLoading ? <Loader2 size={12} className="animate-spin" /> : <Plus size={12} />} Add
              </button>
              <button type="button" onClick={() => { setShowStForm(false); setStError(null); }} style={{ padding: "0.45rem 0.85rem", borderRadius: "6px", fontSize: "0.78rem", background: "var(--surface-3)", color: "var(--text-muted)", border: "none", cursor: "pointer" }}>
                Cancel
              </button>
            </div>
          </form>
        )}

        {!movie.showtimes?.length ? (
          <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", textAlign: "center", padding: "1.5rem 0" }}>No showtimes yet.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {movie.showtimes.map((st) => (
              <div key={st.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0.65rem 0.9rem", borderRadius: "8px", background: "var(--surface-2)", border: "1px solid var(--border)", gap: "0.75rem" }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontWeight: 500, fontSize: "0.85rem", color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{st.hall}</div>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    {new Date(st.start_time).toLocaleString()} · {st.rows * st.seats_per_row} seats · ${(st.price_cents / 100).toFixed(2)}
                  </div>
                </div>
                <button onClick={() => handleDeleteShowtime(st)} style={{ flexShrink: 0, padding: "0.3rem", borderRadius: "5px", color: "var(--danger)", background: "transparent", border: "none", cursor: "pointer" }}>
                  <Trash2 size={13} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
