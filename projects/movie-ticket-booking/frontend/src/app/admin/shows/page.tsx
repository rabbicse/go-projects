"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Ban, X, Calendar } from "lucide-react";
import { adminShows, adminMovies, adminTheaters, type ShowInput } from "@/lib/adminApi";
import type { Show, Movie, Theater, Screen } from "@/types";

// ── Local state types ─────────────────────────────────────────────────────────

interface ShowForm {
  movie_id: string;
  theater_id: string;
  screen_id: string;
  start_time: string;
  end_time: string;
}

const emptyForm = (): ShowForm => ({
  movie_id: "",
  theater_id: "",
  screen_id: "",
  start_time: "",
  end_time: "",
});

// Format ISO string to datetime-local input value (yyyy-MM-ddTHH:mm)
function toDatetimeLocal(iso: string): string {
  if (!iso) return "";
  return iso.slice(0, 16);
}

// Format datetime-local value to RFC3339 for the API
function toISO(local: string): string {
  if (!local) return "";
  return new Date(local).toISOString();
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ShowsPage() {
  const qc = useQueryClient();

  const [modal, setModal] = useState<"create" | "edit" | null>(null);
  const [editingShow, setEditingShow] = useState<Show | null>(null);
  const [form, setForm] = useState<ShowForm>(emptyForm());
  const [formErr, setFormErr] = useState("");
  const [pageErr, setPageErr] = useState("");

  // ── Queries ───────────────────────────────────────────────────────────────
  const { data: shows = [], isLoading } = useQuery({
    queryKey: ["admin", "shows"],
    queryFn: adminShows.list,
  });

  const { data: movies = [] } = useQuery({
    queryKey: ["admin", "movies"],
    queryFn: adminMovies.list,
  });

  const { data: theaters = [] } = useQuery({
    queryKey: ["admin", "theaters"],
    queryFn: adminTheaters.list,
  });

  const { data: screens = [] } = useQuery<Screen[]>({
    queryKey: ["admin", "screens", form.theater_id],
    queryFn: () =>
      form.theater_id
        ? adminTheaters.listScreens(form.theater_id)
        : Promise.resolve([]),
    enabled: !!form.theater_id,
  });

  // Load screens for ALL theaters so the table can show screen names (G9).
  const { data: allScreens = [] } = useQuery<Screen[]>({
    queryKey: ["admin", "all-screens", theaters.map((t: Theater) => t.id).join(",")],
    queryFn: () =>
      Promise.all(theaters.map((t: Theater) => adminTheaters.listScreens(t.id))).then(
        (res) => res.flat(),
      ),
    enabled: theaters.length > 0,
  });

  // ── Lookup maps ───────────────────────────────────────────────────────────
  const movieMap = Object.fromEntries(movies.map((m: Movie) => [m.id, m.title]));
  const screenMap = Object.fromEntries(allScreens.map((sc: Screen) => [sc.id, sc.name]));

  // ── Mutations ─────────────────────────────────────────────────────────────
  const createMut = useMutation({
    mutationFn: (input: ShowInput) => adminShows.create(input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admin", "shows"] });
      closeModal();
    },
    onError: (e: Error) => setFormErr(e.message),
  });

  const updateMut = useMutation({
    mutationFn: ({ id, input }: { id: string; input: ShowInput }) =>
      adminShows.update(id, input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admin", "shows"] });
      closeModal();
    },
    onError: (e: Error) => setFormErr(e.message),
  });

  const cancelMut = useMutation({
    mutationFn: (id: string) => adminShows.cancel(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["admin", "shows"] }),
    onError: (e: Error) => setPageErr(e.message),
  });

  // ── Helpers ───────────────────────────────────────────────────────────────
  async function openCreateModal() {
    setEditingShow(null);
    setForm(emptyForm());
    setFormErr("");
    setModal("create");
  }

  function openEditModal(s: Show) {
    setEditingShow(s);
    setForm({
      movie_id: s.movie_id,
      theater_id: "",
      screen_id: s.screen_id,
      start_time: toDatetimeLocal(s.start_time),
      end_time: toDatetimeLocal(s.end_time),
    });
    setFormErr("");
    setModal("edit");
  }

  function closeModal() {
    setModal(null);
    setFormErr("");
  }

  function submitForm() {
    setFormErr("");
    if (!form.movie_id) { setFormErr("Movie is required"); return; }
    if (!form.screen_id) { setFormErr("Screen is required"); return; }
    if (!form.start_time) { setFormErr("Start time is required"); return; }
    if (!form.end_time) { setFormErr("End time is required"); return; }
    const start = new Date(form.start_time);
    const end = new Date(form.end_time);
    if (end <= start) { setFormErr("End time must be after start time"); return; }

    const input: ShowInput = {
      movie_id: form.movie_id,
      screen_id: form.screen_id,
      start_time: toISO(form.start_time),
      end_time: toISO(form.end_time),
    };

    if (modal === "edit" && editingShow) {
      updateMut.mutate({ id: editingShow.id, input });
    } else {
      createMut.mutate(input);
    }
  }

  const busy = createMut.isPending || updateMut.isPending;

  const statusBadge = (status: string) => (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: "12px",
        fontSize: "0.72rem",
        fontWeight: 600,
        background:
          status === "scheduled"
            ? "rgba(99,102,241,0.12)"
            : "rgba(148,163,184,0.15)",
        color: status === "scheduled" ? "var(--accent)" : "var(--text-dim)",
      }}
    >
      {status.toUpperCase()}
    </span>
  );

  const fmtTime = (iso: string) =>
    iso
      ? new Date(iso).toLocaleString("en-GB", {
          day: "2-digit",
          month: "short",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        })
      : "—";

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "1.25rem", fontWeight: 700, margin: 0 }}>Shows</h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.82rem", margin: "0.25rem 0 0" }}>
            Schedule movie screenings on screens
          </p>
        </div>
        <button
          onClick={openCreateModal}
          style={{
            display: "flex", alignItems: "center", gap: "0.4rem",
            padding: "0.5rem 1rem", borderRadius: "8px",
            background: "var(--accent)", color: "#fff",
            border: "none", cursor: "pointer", fontSize: "0.83rem", fontWeight: 600,
          }}
        >
          <Plus size={14} /> New Show
        </button>
      </div>

      {/* Page error */}
      {pageErr && (
        <div
          style={{
            background: "rgba(239,68,68,0.1)", border: "1px solid var(--danger)",
            color: "var(--danger)", borderRadius: "8px", padding: "0.75rem 1rem",
            marginBottom: "1rem", fontSize: "0.83rem", display: "flex",
            justifyContent: "space-between", alignItems: "center",
          }}
        >
          {pageErr}
          <button onClick={() => setPageErr("")} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--danger)" }}>
            <X size={14} />
          </button>
        </div>
      )}

      {/* Shows table */}
      {isLoading ? (
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>Loading…</p>
      ) : shows.length === 0 ? (
        <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)", fontSize: "0.85rem" }}>
          No shows scheduled yet.
        </div>
      ) : (
        <div style={{ border: "1px solid var(--border)", borderRadius: "10px", overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "var(--surface-2)", borderBottom: "1px solid var(--border)" }}>
                {["Movie", "Screen", "Start", "End", "Status", "Actions"].map((h) => (
                  <th key={h} style={{ padding: "0.65rem 1rem", textAlign: "left", fontSize: "0.75rem", fontWeight: 600, color: "var(--text-muted)", letterSpacing: "0.04em" }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shows.map((s, idx) => (
                <tr
                  key={s.id}
                  style={{ borderBottom: idx < shows.length - 1 ? "1px solid var(--border)" : "none" }}
                >
                  <td style={{ padding: "0.75rem 1rem", fontWeight: 500, fontSize: "0.85rem" }}>
                    {movieMap[s.movie_id] ?? s.movie_id.slice(0, 8) + "…"}
                  </td>
                  <td style={{ padding: "0.75rem 1rem", color: "var(--text-muted)", fontSize: "0.83rem" }}>
                    {screenMap[s.screen_id] ?? s.screen_id.slice(0, 8) + "…"}
                  </td>
                  <td style={{ padding: "0.75rem 1rem", color: "var(--text-muted)", fontSize: "0.82rem", whiteSpace: "nowrap" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.3rem" }}>
                      <Calendar size={11} />
                      {fmtTime(s.start_time)}
                    </div>
                  </td>
                  <td style={{ padding: "0.75rem 1rem", color: "var(--text-muted)", fontSize: "0.82rem", whiteSpace: "nowrap" }}>
                    {fmtTime(s.end_time)}
                  </td>
                  <td style={{ padding: "0.75rem 1rem" }}>{statusBadge(s.status)}</td>
                  <td style={{ padding: "0.75rem 1rem" }}>
                    <div style={{ display: "flex", gap: "0.5rem" }}>
                      {s.status === "scheduled" && (
                        <>
                          <button
                            onClick={() => openEditModal(s)}
                            style={{ padding: "4px 6px", borderRadius: "6px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", color: "var(--text-muted)" }}
                          >
                            <Pencil size={12} />
                          </button>
                          <button
                            onClick={() => cancelMut.mutate(s.id)}
                            style={{ padding: "4px 6px", borderRadius: "6px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", color: "var(--danger)" }}
                            title="Cancel show"
                          >
                            <Ban size={12} />
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Create/Edit modal */}
      {modal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 50 }}>
          <div style={{ background: "var(--surface)", borderRadius: "12px", padding: "1.5rem", width: "460px", maxWidth: "90vw" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem" }}>
              <h2 style={{ margin: 0, fontSize: "1rem", fontWeight: 700 }}>
                {modal === "edit" ? "Edit Show" : "Schedule Show"}
              </h2>
              <button onClick={closeModal} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}>
                <X size={16} />
              </button>
            </div>

            {formErr && (
              <p style={{ color: "var(--danger)", fontSize: "0.8rem", margin: "0 0 0.75rem", padding: "0.5rem 0.75rem", background: "rgba(239,68,68,0.08)", borderRadius: "6px" }}>
                {formErr}
              </p>
            )}

            {/* Movie select */}
            <div style={{ marginBottom: "1rem" }}>
              <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "0.3rem" }}>Movie</label>
              <select
                value={form.movie_id}
                onChange={(e) => setForm((f) => ({ ...f, movie_id: e.target.value }))}
                style={{ width: "100%", padding: "0.5rem 0.75rem", borderRadius: "7px", border: "1px solid var(--border)", background: "var(--surface-2)", color: "var(--text)", fontSize: "0.85rem" }}
              >
                <option value="">Select a movie…</option>
                {movies.map((m: Movie) => (
                  <option key={m.id} value={m.id}>{m.title}</option>
                ))}
              </select>
            </div>

            {/* Theater select (for filtering screens) */}
            <div style={{ marginBottom: "1rem" }}>
              <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "0.3rem" }}>Theater</label>
              <select
                value={form.theater_id}
                onChange={(e) => setForm((f) => ({ ...f, theater_id: e.target.value, screen_id: "" }))}
                style={{ width: "100%", padding: "0.5rem 0.75rem", borderRadius: "7px", border: "1px solid var(--border)", background: "var(--surface-2)", color: "var(--text)", fontSize: "0.85rem" }}
              >
                <option value="">Select a theater…</option>
                {theaters.filter((t: Theater) => t.status === "active").map((t: Theater) => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
            </div>

            {/* Screen select */}
            <div style={{ marginBottom: "1rem" }}>
              <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "0.3rem" }}>Screen</label>
              <select
                value={form.screen_id}
                onChange={(e) => setForm((f) => ({ ...f, screen_id: e.target.value }))}
                disabled={!form.theater_id}
                style={{ width: "100%", padding: "0.5rem 0.75rem", borderRadius: "7px", border: "1px solid var(--border)", background: "var(--surface-2)", color: "var(--text)", fontSize: "0.85rem", opacity: !form.theater_id ? 0.5 : 1 }}
              >
                <option value="">
                  {form.theater_id ? "Select a screen…" : "Select a theater first"}
                </option>
                {screens.filter((sc: Screen) => sc.status === "active").map((sc: Screen) => (
                  <option key={sc.id} value={sc.id}>
                    {sc.name} ({sc.capacity} seats)
                  </option>
                ))}
              </select>
            </div>

            {/* Start / End time */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginBottom: "1.25rem" }}>
              {[
                { label: "Start time", key: "start_time" as const },
                { label: "End time", key: "end_time" as const },
              ].map(({ label, key }) => (
                <div key={key}>
                  <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "0.3rem" }}>{label}</label>
                  <input
                    type="datetime-local"
                    value={form[key]}
                    onChange={(e) => setForm((f) => ({ ...f, [key]: e.target.value }))}
                    style={{ width: "100%", padding: "0.5rem 0.75rem", borderRadius: "7px", border: "1px solid var(--border)", background: "var(--surface-2)", color: "var(--text)", fontSize: "0.82rem", boxSizing: "border-box" }}
                  />
                </div>
              ))}
            </div>

            <div style={{ display: "flex", gap: "0.75rem", justifyContent: "flex-end" }}>
              <button onClick={closeModal} style={{ padding: "0.5rem 1rem", borderRadius: "7px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", fontSize: "0.83rem" }}>
                Cancel
              </button>
              <button
                onClick={submitForm}
                disabled={busy}
                style={{ padding: "0.5rem 1rem", borderRadius: "7px", background: "var(--accent)", color: "#fff", border: "none", cursor: "pointer", fontSize: "0.83rem", fontWeight: 600, opacity: busy ? 0.6 : 1 }}
              >
                {busy ? "Saving…" : modal === "edit" ? "Save" : "Schedule"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
