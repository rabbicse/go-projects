"use client";

import { useRef, useState } from "react";
import Image from "next/image";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus, Pencil, Trash2, Eye, EyeOff, Film,
  Loader2, Star, Clock, ImagePlus, X,
} from "lucide-react";
import { adminMovies, AdminApiError, type MovieInput } from "@/lib/adminApi";
import type { Movie } from "@/types";

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDuration(min: number): string {
  const h = Math.floor(min / 60);
  const m = min % 60;
  if (h === 0) return `${m}m`;
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

function splitGenres(s: string): string[] {
  return s.split(",").map((g) => g.trim()).filter(Boolean);
}

// ── Form state ────────────────────────────────────────────────────────────────

interface FormState {
  title: string;
  genre: string;       // comma-separated string for the input
  rating: string;
  duration_min: string;
  description: string;
  poster_url: string;
}

const emptyForm = (): FormState => ({
  title: "",
  genre: "",
  rating: "7.0",
  duration_min: "120",
  description: "",
  poster_url: "",
});

function movieToForm(m: Movie): FormState {
  return {
    title: m.title,
    genre: m.genre.join(", "),
    rating: m.rating.toString(),
    duration_min: m.duration_min.toString(),
    description: m.description ?? "",
    poster_url: m.poster_url ?? "",
  };
}

function formToInput(f: FormState): MovieInput {
  return {
    title: f.title.trim(),
    genre: splitGenres(f.genre),
    rating: parseFloat(f.rating) || 0,
    duration_min: parseInt(f.duration_min, 10) || 1,
    description: f.description.trim() || undefined,
    poster_url: f.poster_url.trim() || undefined,
  };
}

function validateForm(f: FormState): string | null {
  if (!f.title.trim()) return "Title is required.";
  if (!splitGenres(f.genre).length) return "At least one category is required.";
  const r = parseFloat(f.rating);
  if (isNaN(r) || r < 0 || r > 10) return "Rating must be between 0 and 10.";
  const d = parseInt(f.duration_min, 10);
  if (isNaN(d) || d < 1) return "Duration must be at least 1 minute.";
  return null;
}

// ── Shared styles ─────────────────────────────────────────────────────────────

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "0.55rem 0.75rem",
  borderRadius: "7px",
  border: "1px solid var(--border)",
  background: "var(--surface-2)",
  color: "var(--text)",
  fontSize: "0.83rem",
  outline: "none",
  fontFamily: "inherit",
};

const iconBtn: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: "0.38rem",
  borderRadius: "6px",
  border: "1px solid var(--border)",
  background: "var(--surface-2)",
  cursor: "pointer",
};

// ── Field wrapper ─────────────────────────────────────────────────────────────

function Field({
  label, hint, required, children,
}: {
  label: string; hint?: string; required?: boolean; children: React.ReactNode;
}) {
  return (
    <div>
      <label
        style={{
          display: "flex", alignItems: "center", gap: "0.3rem",
          fontSize: "0.72rem", fontWeight: 600, color: "var(--text-muted)",
          textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: "0.4rem",
        }}
      >
        {label}
        {required && <span style={{ color: "var(--danger)" }}>*</span>}
        {hint && (
          <span style={{ color: "var(--text-dim)", fontWeight: 400, textTransform: "none", letterSpacing: 0 }}>
            — {hint}
          </span>
        )}
      </label>
      {children}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AdminMoviesPage() {
  const qc = useQueryClient();

  const { data: movies = [], isLoading, error: loadError } = useQuery<Movie[], Error>({
    queryKey: ["admin", "movies"],
    queryFn: adminMovies.list,
    retry: 1,
  });

  // ── Modal state ───────────────────────────────────────────────────────────

  const [modalMode, setModalMode] = useState<"create" | "edit" | null>(null);
  const [editTarget, setEditTarget] = useState<Movie | null>(null);
  const [form, setForm] = useState<FormState>(emptyForm());
  const [formError, setFormError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Movie | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);

  // Ref map for per-row hidden file inputs
  const posterInputRef = useRef<HTMLInputElement>(null);
  const [pendingUploadId, setPendingUploadId] = useState<string | null>(null);

  // ── Helpers ───────────────────────────────────────────────────────────────

  function invalidate() {
    void qc.invalidateQueries({ queryKey: ["admin", "movies"] });
  }

  function openCreate() {
    setForm(emptyForm());
    setFormError(null);
    setEditTarget(null);
    setModalMode("create");
  }

  function openEdit(m: Movie) {
    setForm(movieToForm(m));
    setFormError(null);
    setEditTarget(m);
    setModalMode("edit");
  }

  function closeModal() {
    setModalMode(null);
    setEditTarget(null);
    setFormError(null);
  }

  function dismissPageError() {
    setPageError(null);
  }

  // ── Mutations ─────────────────────────────────────────────────────────────

  const createMut = useMutation({
    mutationFn: (input: MovieInput) => adminMovies.create(input),
    onSuccess: () => { invalidate(); closeModal(); },
    onError: (err: Error) => setFormError(err.message),
  });

  const updateMut = useMutation({
    mutationFn: ({ id, input }: { id: string; input: MovieInput }) =>
      adminMovies.update(id, input),
    onSuccess: () => { invalidate(); closeModal(); },
    onError: (err: Error) => setFormError(err.message),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => adminMovies.remove(id),
    onSuccess: () => { invalidate(); setDeleteTarget(null); },
    onError: (err: Error) => setPageError(err.message),
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, publish }: { id: string; publish: boolean }) =>
      publish ? adminMovies.publish(id) : adminMovies.unpublish(id),
    onSuccess: () => { invalidate(); setPageError(null); },
    onError: (err: Error) => {
      const msg =
        err instanceof AdminApiError && err.status === 422
          ? "Cannot publish: movie has validation errors. Edit and fix it first."
          : err.message;
      setPageError(msg);
    },
  });

  const posterMut = useMutation({
    mutationFn: ({ id, file }: { id: string; file: File }) =>
      adminMovies.uploadPoster(id, file),
    onSuccess: (data) => {
      // If the edit modal is open for the same movie, update the URL field.
      if (editTarget && pendingUploadId === editTarget.id) {
        setForm((f) => ({ ...f, poster_url: data.poster_url }));
      }
      invalidate();
      setPendingUploadId(null);
      setPageError(null);
    },
    onError: (err: Error) => {
      setPendingUploadId(null);
      setPageError(err.message);
    },
  });

  // ── Form submit ───────────────────────────────────────────────────────────

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const err = validateForm(form);
    if (err) { setFormError(err); return; }
    const input = formToInput(form);
    if (modalMode === "create") {
      createMut.mutate(input);
    } else if (editTarget) {
      updateMut.mutate({ id: editTarget.id, input });
    }
  }

  // ── Poster upload trigger (list row) ──────────────────────────────────────

  function triggerPosterUpload(movieId: string) {
    setPendingUploadId(movieId);
    posterInputRef.current?.click();
  }

  function handlePosterFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file && pendingUploadId) {
      posterMut.mutate({ id: pendingUploadId, file });
    }
    e.target.value = ""; // reset so same file triggers onChange again
  }

  // ── Poster upload inside edit modal ───────────────────────────────────────

  const modalPosterRef = useRef<HTMLInputElement>(null);

  function handleModalPosterChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file && editTarget) {
      setPendingUploadId(editTarget.id);
      posterMut.mutate({ id: editTarget.id, file });
    }
    e.target.value = "";
  }

  const savePending = createMut.isPending || updateMut.isPending;

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div>
      {/* Hidden file input for list-row poster upload */}
      <input
        ref={posterInputRef}
        type="file"
        accept=".jpg,.jpeg,.png,.webp"
        style={{ display: "none" }}
        onChange={handlePosterFileChange}
      />

      {/* ── Page header ── */}
      <div
        style={{
          display: "flex", alignItems: "center",
          justifyContent: "space-between", marginBottom: "1.75rem",
        }}
      >
        <div>
          <h1 style={{ fontSize: "1.4rem", fontWeight: 700, color: "var(--text)", marginBottom: "0.2rem" }}>
            Movies
          </h1>
          <p style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
            {movies.length} title{movies.length !== 1 ? "s" : ""} in catalogue
          </p>
        </div>
        <button
          onClick={openCreate}
          style={{
            display: "flex", alignItems: "center", gap: "0.4rem",
            padding: "0.55rem 1rem", borderRadius: "8px",
            background: "var(--accent)", color: "#000",
            border: "none", cursor: "pointer",
            fontSize: "0.83rem", fontWeight: 600,
          }}
        >
          <Plus size={14} />
          New Movie
        </button>
      </div>

      {/* ── Page error banner ── */}
      {pageError && (
        <div
          style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "0.65rem 1rem", marginBottom: "1rem", borderRadius: "8px",
            border: "1px solid color-mix(in srgb, var(--danger) 35%, transparent)",
            background: "color-mix(in srgb, var(--danger) 10%, transparent)",
            fontSize: "0.82rem", color: "var(--danger)",
          }}
        >
          {pageError}
          <button
            onClick={dismissPageError}
            style={{ background: "none", border: "none", color: "var(--danger)", cursor: "pointer", lineHeight: 1 }}
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* ── Loading ── */}
      {isLoading && (
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", color: "var(--text-muted)" }}>
          <Loader2 size={15} className="animate-spin" />
          <span style={{ fontSize: "0.82rem" }}>Loading…</span>
        </div>
      )}

      {/* ── Load error ── */}
      {loadError && (
        <div
          style={{
            padding: "0.75rem 1rem", borderRadius: "8px",
            border: "1px solid var(--danger)",
            background: "color-mix(in srgb, var(--danger) 8%, transparent)",
            fontSize: "0.82rem", color: "var(--danger)",
          }}
        >
          {loadError.message}
        </div>
      )}

      {/* ── Empty state ── */}
      {!isLoading && !loadError && movies.length === 0 && (
        <div style={{ textAlign: "center", paddingTop: "5rem", color: "var(--text-muted)" }}>
          <Film size={36} style={{ marginBottom: "0.75rem", opacity: 0.3 }} />
          <p style={{ fontSize: "0.83rem", marginBottom: "1.25rem" }}>
            No movies yet. Add the first one.
          </p>
          <button
            onClick={openCreate}
            style={{
              padding: "0.55rem 1.1rem", borderRadius: "8px",
              background: "var(--accent)", color: "#000",
              border: "none", cursor: "pointer",
              fontSize: "0.83rem", fontWeight: 600,
            }}
          >
            Add Movie
          </button>
        </div>
      )}

      {/* ── Movie table ── */}
      {movies.length > 0 && (
        <div style={{ border: "1px solid var(--border)", borderRadius: "10px", overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
            <thead>
              <tr style={{ background: "var(--surface-2)", borderBottom: "1px solid var(--border)" }}>
                {["Poster", "Title / Categories", "Rating", "Duration", "Status", "Actions"].map((h) => (
                  <th
                    key={h}
                    style={{
                      padding: "0.6rem 1rem", textAlign: "left",
                      fontWeight: 600, color: "var(--text-muted)",
                      fontSize: "0.7rem", textTransform: "uppercase", letterSpacing: "0.06em",
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {movies.map((m, i) => {
                const isUploading = posterMut.isPending && pendingUploadId === m.id;
                return (
                  <tr
                    key={m.id}
                    style={{
                      borderBottom: i < movies.length - 1 ? "1px solid var(--border)" : "none",
                      background: "var(--surface)",
                    }}
                  >
                    {/* Poster */}
                    <td style={{ padding: "0.75rem 1rem", width: "56px" }}>
                      <div
                        style={{
                          width: "36px", height: "50px", borderRadius: "5px",
                          overflow: "hidden", flexShrink: 0, position: "relative",
                          background: "var(--surface-3)",
                          display: "flex", alignItems: "center", justifyContent: "center",
                        }}
                      >
                        {isUploading ? (
                          <Loader2 size={14} className="animate-spin" style={{ color: "var(--text-dim)" }} />
                        ) : m.poster_url ? (
                          <Image
                            src={m.poster_url} alt={m.title}
                            fill sizes="36px"
                            style={{ objectFit: "cover" }}
                            unoptimized
                          />
                        ) : (
                          <Film size={14} style={{ color: "var(--text-dim)" }} />
                        )}
                      </div>
                    </td>

                    {/* Title + categories */}
                    <td style={{ padding: "0.75rem 1rem", maxWidth: "260px" }}>
                      <div
                        style={{
                          fontWeight: 600, color: "var(--text)",
                          marginBottom: "0.3rem", whiteSpace: "nowrap",
                          overflow: "hidden", textOverflow: "ellipsis",
                        }}
                      >
                        {m.title}
                      </div>
                      {m.description && (
                        <div
                          style={{
                            fontSize: "0.75rem", color: "var(--text-muted)",
                            marginBottom: "0.3rem",
                            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                          }}
                        >
                          {m.description}
                        </div>
                      )}
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.2rem" }}>
                        {m.genre.map((g) => (
                          <span
                            key={g}
                            style={{
                              fontSize: "0.66rem", padding: "1px 6px", borderRadius: "4px",
                              background: "var(--surface-3)", color: "var(--text-muted)",
                              border: "1px solid var(--border)",
                            }}
                          >
                            {g}
                          </span>
                        ))}
                      </div>
                    </td>

                    {/* Rating */}
                    <td style={{ padding: "0.75rem 1rem", whiteSpace: "nowrap" }}>
                      <span
                        style={{
                          display: "flex", alignItems: "center", gap: "0.25rem",
                          color: "var(--warning)",
                        }}
                      >
                        <Star size={12} />
                        {m.rating.toFixed(1)}
                      </span>
                    </td>

                    {/* Duration */}
                    <td style={{ padding: "0.75rem 1rem", whiteSpace: "nowrap" }}>
                      <span
                        style={{
                          display: "flex", alignItems: "center", gap: "0.25rem",
                          color: "var(--text-muted)",
                        }}
                      >
                        <Clock size={12} />
                        {fmtDuration(m.duration_min)}
                      </span>
                    </td>

                    {/* Status */}
                    <td style={{ padding: "0.75rem 1rem" }}>
                      <span
                        style={{
                          fontSize: "0.67rem", padding: "2px 8px", borderRadius: "5px",
                          fontWeight: 700, letterSpacing: "0.04em",
                          background: m.published
                            ? "color-mix(in srgb, var(--success) 15%, transparent)"
                            : "var(--surface-3)",
                          color: m.published ? "var(--success)" : "var(--text-dim)",
                          border: `1px solid ${m.published
                            ? "color-mix(in srgb, var(--success) 35%, transparent)"
                            : "var(--border)"}`,
                        }}
                      >
                        {m.published ? "PUBLISHED" : "DRAFT"}
                      </span>
                    </td>

                    {/* Actions */}
                    <td style={{ padding: "0.75rem 1rem" }}>
                      <div
                        style={{
                          display: "flex", alignItems: "center",
                          gap: "0.3rem", justifyContent: "flex-end",
                        }}
                      >
                        {/* Upload poster */}
                        <button
                          onClick={() => triggerPosterUpload(m.id)}
                          disabled={isUploading}
                          title="Upload poster"
                          style={{ ...iconBtn, color: "var(--text-muted)" }}
                        >
                          <ImagePlus size={13} />
                        </button>

                        {/* Publish / Unpublish toggle */}
                        <button
                          onClick={() => toggleMut.mutate({ id: m.id, publish: !m.published })}
                          disabled={toggleMut.isPending}
                          title={m.published ? "Unpublish" : "Publish"}
                          style={{
                            ...iconBtn,
                            color: m.published ? "var(--success)" : "var(--text-muted)",
                          }}
                        >
                          {m.published ? <EyeOff size={13} /> : <Eye size={13} />}
                        </button>

                        {/* Edit */}
                        <button
                          onClick={() => openEdit(m)}
                          title="Edit"
                          style={{ ...iconBtn, color: "var(--text-muted)" }}
                        >
                          <Pencil size={13} />
                        </button>

                        {/* Delete */}
                        <button
                          onClick={() => setDeleteTarget(m)}
                          title="Delete"
                          style={{ ...iconBtn, color: "var(--danger)" }}
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Create / Edit modal ── */}
      {modalMode && (
        <div
          style={{
            position: "fixed", inset: 0, zIndex: 50,
            background: "rgba(0,0,0,0.75)",
            display: "flex", alignItems: "center", justifyContent: "center",
            padding: "1rem",
          }}
        >
          <div
            style={{
              background: "var(--surface)", borderRadius: "12px",
              border: "1px solid var(--border)",
              width: "100%", maxWidth: "520px",
              maxHeight: "92vh", overflowY: "auto",
              padding: "1.5rem",
            }}
          >
            {/* Modal header */}
            <div
              style={{
                display: "flex", alignItems: "center",
                justifyContent: "space-between", marginBottom: "1.25rem",
              }}
            >
              <h2 style={{ fontSize: "1rem", fontWeight: 700, color: "var(--text)" }}>
                {modalMode === "create" ? "New Movie" : "Edit Movie"}
              </h2>
              <button
                onClick={closeModal}
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}
              >
                <X size={16} />
              </button>
            </div>

            {/* Poster section — edit only */}
            {modalMode === "edit" && editTarget && (
              <div style={{ marginBottom: "1.25rem" }}>
                <input
                  ref={modalPosterRef}
                  type="file"
                  accept=".jpg,.jpeg,.png,.webp"
                  style={{ display: "none" }}
                  onChange={handleModalPosterChange}
                />
                <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
                  {/* Thumbnail */}
                  <div
                    style={{
                      width: "54px", height: "72px", borderRadius: "6px",
                      overflow: "hidden", position: "relative", flexShrink: 0,
                      background: "var(--surface-3)",
                      display: "flex", alignItems: "center", justifyContent: "center",
                      border: "1px solid var(--border)",
                    }}
                  >
                    {posterMut.isPending && pendingUploadId === editTarget.id ? (
                      <Loader2 size={16} className="animate-spin" style={{ color: "var(--text-dim)" }} />
                    ) : form.poster_url ? (
                      <Image
                        src={form.poster_url} alt="Poster"
                        fill sizes="54px"
                        style={{ objectFit: "cover" }}
                        unoptimized
                      />
                    ) : (
                      <Film size={18} style={{ color: "var(--text-dim)" }} />
                    )}
                  </div>
                  {/* Upload button */}
                  <div>
                    <button
                      type="button"
                      onClick={() => modalPosterRef.current?.click()}
                      disabled={posterMut.isPending}
                      style={{
                        display: "flex", alignItems: "center", gap: "0.4rem",
                        padding: "0.45rem 0.85rem", borderRadius: "7px",
                        border: "1px solid var(--border)", background: "var(--surface-2)",
                        color: "var(--text-muted)", cursor: "pointer",
                        fontSize: "0.78rem", marginBottom: "0.35rem",
                      }}
                    >
                      <ImagePlus size={13} />
                      {posterMut.isPending && pendingUploadId === editTarget.id
                        ? "Uploading…"
                        : form.poster_url ? "Change Poster" : "Upload Poster"}
                    </button>
                    <p style={{ fontSize: "0.7rem", color: "var(--text-dim)" }}>
                      JPG, PNG, WebP · max 4 MB
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <Field label="Title" required>
                <input
                  value={form.title}
                  onChange={(e) => setForm({ ...form, title: e.target.value })}
                  placeholder="e.g. Inception"
                  autoFocus={modalMode === "create"}
                  style={inputStyle}
                />
              </Field>

              <Field label="Categories" hint="comma-separated" required>
                <input
                  value={form.genre}
                  onChange={(e) => setForm({ ...form, genre: e.target.value })}
                  placeholder="e.g. Action, Sci-Fi, Thriller"
                  style={inputStyle}
                />
              </Field>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
                <Field label="Rating" hint="0–10" required>
                  <input
                    type="number" step="0.1" min="0" max="10"
                    value={form.rating}
                    onChange={(e) => setForm({ ...form, rating: e.target.value })}
                    style={inputStyle}
                  />
                </Field>
                <Field label="Duration" hint="minutes" required>
                  <input
                    type="number" min="1"
                    value={form.duration_min}
                    onChange={(e) => setForm({ ...form, duration_min: e.target.value })}
                    style={inputStyle}
                  />
                </Field>
              </div>

              <Field label="Description">
                <textarea
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  rows={3}
                  placeholder="Short synopsis…"
                  style={{ ...inputStyle, resize: "vertical" }}
                />
              </Field>

              {/* Poster URL — shown in both modes as a fallback */}
              <Field label="Poster URL" hint="or upload above">
                <input
                  value={form.poster_url}
                  onChange={(e) => setForm({ ...form, poster_url: e.target.value })}
                  placeholder="https://…/poster.jpg"
                  style={inputStyle}
                />
              </Field>

              {/* Form error */}
              {formError && (
                <div
                  style={{
                    fontSize: "0.8rem", color: "var(--danger)",
                    padding: "0.5rem 0.75rem", borderRadius: "6px",
                    background: "color-mix(in srgb, var(--danger) 10%, transparent)",
                    border: "1px solid color-mix(in srgb, var(--danger) 30%, transparent)",
                  }}
                >
                  {formError}
                </div>
              )}

              {/* Buttons */}
              <div
                style={{
                  display: "flex", justifyContent: "flex-end",
                  gap: "0.5rem", paddingTop: "0.25rem",
                }}
              >
                <button
                  type="button"
                  onClick={closeModal}
                  style={{
                    padding: "0.55rem 1rem", borderRadius: "8px",
                    border: "1px solid var(--border)", background: "transparent",
                    color: "var(--text-muted)", cursor: "pointer", fontSize: "0.83rem",
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savePending}
                  style={{
                    padding: "0.55rem 1.1rem", borderRadius: "8px",
                    border: "none", background: "var(--accent)", color: "#000",
                    cursor: savePending ? "not-allowed" : "pointer",
                    fontSize: "0.83rem", fontWeight: 600,
                    opacity: savePending ? 0.7 : 1,
                  }}
                >
                  {savePending ? "Saving…" : modalMode === "create" ? "Create Movie" : "Save Changes"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Delete confirmation ── */}
      {deleteTarget && (
        <div
          style={{
            position: "fixed", inset: 0, zIndex: 50,
            background: "rgba(0,0,0,0.75)",
            display: "flex", alignItems: "center", justifyContent: "center",
            padding: "1rem",
          }}
        >
          <div
            style={{
              background: "var(--surface)", borderRadius: "12px",
              border: "1px solid var(--border)",
              width: "100%", maxWidth: "380px",
              padding: "1.5rem",
            }}
          >
            <h2 style={{ fontSize: "1rem", fontWeight: 700, color: "var(--text)", marginBottom: "0.5rem" }}>
              Delete movie?
            </h2>
            <p
              style={{
                fontSize: "0.83rem", color: "var(--text-muted)",
                lineHeight: 1.6, marginBottom: "1.25rem",
              }}
            >
              <strong style={{ color: "var(--text)" }}>{deleteTarget.title}</strong> and all its
              showtimes will be permanently removed. This cannot be undone.
            </p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
              <button
                onClick={() => setDeleteTarget(null)}
                style={{
                  padding: "0.55rem 1rem", borderRadius: "8px",
                  border: "1px solid var(--border)", background: "transparent",
                  color: "var(--text-muted)", cursor: "pointer", fontSize: "0.83rem",
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => deleteMut.mutate(deleteTarget.id)}
                disabled={deleteMut.isPending}
                style={{
                  padding: "0.55rem 1rem", borderRadius: "8px",
                  border: "none", background: "var(--danger)", color: "#fff",
                  cursor: deleteMut.isPending ? "not-allowed" : "pointer",
                  fontSize: "0.83rem", fontWeight: 600,
                  opacity: deleteMut.isPending ? 0.7 : 1,
                }}
              >
                {deleteMut.isPending ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
