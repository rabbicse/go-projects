"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Ban, Monitor, X, ChevronDown, ChevronRight } from "lucide-react";
import {
  adminTheaters,
  type TheaterInput,
  type ScreenInput,
  type RowCategoryInput,
} from "@/lib/adminApi";
import type { Theater, Screen } from "@/types";

// ── Local state types ─────────────────────────────────────────────────────────

interface TheaterForm {
  name: string;
  location: string;
}

interface ScreenForm {
  name: string;
  rows_count: string;
  seats_per_row: string;
  vip_rows: string;
  premium_rows: string;
}

const emptyTheaterForm = (): TheaterForm => ({ name: "", location: "" });
const emptyScreenForm = (): ScreenForm => ({
  name: "",
  rows_count: "8",
  seats_per_row: "12",
  vip_rows: "",
  premium_rows: "",
});

// Parse comma-separated row labels like "A,B" → [{row:"A",category:"vip"}, ...]
function parseRowCategories(vipRows: string, premiumRows: string): RowCategoryInput[] {
  const cats: RowCategoryInput[] = [];
  vipRows.split(",").map((r) => r.trim().toUpperCase()).filter(Boolean).forEach((r) =>
    cats.push({ row: r, category: "vip" })
  );
  premiumRows.split(",").map((r) => r.trim().toUpperCase()).filter(Boolean).forEach((r) =>
    cats.push({ row: r, category: "premium" })
  );
  return cats;
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function TheatersPage() {
  const qc = useQueryClient();

  // ── Theater modal state ───────────────────────────────────────────────────
  const [theaterModal, setTheaterModal] = useState<"create" | "edit" | null>(null);
  const [editingTheater, setEditingTheater] = useState<Theater | null>(null);
  const [theaterForm, setTheaterForm] = useState<TheaterForm>(emptyTheaterForm());
  const [theaterErr, setTheaterErr] = useState("");

  // ── Screen panel state ────────────────────────────────────────────────────
  const [expandedTheater, setExpandedTheater] = useState<string | null>(null);
  const [screenModal, setScreenModal] = useState<"create" | "edit" | null>(null);
  const [editingScreen, setEditingScreen] = useState<Screen | null>(null);
  const [screenForm, setScreenForm] = useState<ScreenForm>(emptyScreenForm());
  const [screenErr, setScreenErr] = useState("");

  // ── Page-level error ──────────────────────────────────────────────────────
  const [pageErr, setPageErr] = useState("");

  // ── Disable-theater confirmation ──────────────────────────────────────────
  const [confirmDisable, setConfirmDisable] = useState<Theater | null>(null);

  // ── Queries ───────────────────────────────────────────────────────────────
  const { data: theaters = [], isLoading } = useQuery({
    queryKey: ["admin", "theaters"],
    queryFn: adminTheaters.list,
  });

  const { data: screens = [] } = useQuery({
    queryKey: ["admin", "screens", expandedTheater],
    queryFn: () =>
      expandedTheater ? adminTheaters.listScreens(expandedTheater) : Promise.resolve([]),
    enabled: !!expandedTheater,
  });

  // ── Theater mutations ─────────────────────────────────────────────────────
  const createTheaterMut = useMutation({
    mutationFn: (input: TheaterInput) => adminTheaters.create(input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admin", "theaters"] });
      closeTheaterModal();
    },
    onError: (e: Error) => setTheaterErr(e.message),
  });

  const updateTheaterMut = useMutation({
    mutationFn: ({ id, input }: { id: string; input: TheaterInput }) =>
      adminTheaters.update(id, input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admin", "theaters"] });
      closeTheaterModal();
    },
    onError: (e: Error) => setTheaterErr(e.message),
  });

  const disableTheaterMut = useMutation({
    mutationFn: (id: string) => adminTheaters.disable(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["admin", "theaters"] }),
    onError: (e: Error) => setPageErr(e.message),
  });

  // ── Screen mutations ──────────────────────────────────────────────────────
  const createScreenMut = useMutation({
    mutationFn: ({ theaterId, input }: { theaterId: string; input: ScreenInput }) =>
      adminTheaters.createScreen(theaterId, input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admin", "screens", expandedTheater] });
      closeScreenModal();
    },
    onError: (e: Error) => setScreenErr(e.message),
  });

  const updateScreenMut = useMutation({
    mutationFn: ({
      theaterId,
      screenId,
      input,
    }: {
      theaterId: string;
      screenId: string;
      input: ScreenInput;
    }) => adminTheaters.updateScreen(theaterId, screenId, input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["admin", "screens", expandedTheater] });
      closeScreenModal();
    },
    onError: (e: Error) => setScreenErr(e.message),
  });

  const disableScreenMut = useMutation({
    mutationFn: ({ theaterId, screenId }: { theaterId: string; screenId: string }) =>
      adminTheaters.disableScreen(theaterId, screenId),
    onSuccess: () =>
      void qc.invalidateQueries({ queryKey: ["admin", "screens", expandedTheater] }),
    onError: (e: Error) => setPageErr(e.message),
  });

  // ── Helpers ───────────────────────────────────────────────────────────────
  function openCreateTheater() {
    setEditingTheater(null);
    setTheaterForm(emptyTheaterForm());
    setTheaterErr("");
    setTheaterModal("create");
  }

  function openEditTheater(t: Theater) {
    setEditingTheater(t);
    setTheaterForm({ name: t.name, location: t.location });
    setTheaterErr("");
    setTheaterModal("edit");
  }

  function closeTheaterModal() {
    setTheaterModal(null);
    setTheaterErr("");
  }

  function submitTheater() {
    setTheaterErr("");
    const input: TheaterInput = { name: theaterForm.name.trim(), location: theaterForm.location.trim() };
    if (!input.name) { setTheaterErr("Name is required"); return; }
    if (!input.location) { setTheaterErr("Location is required"); return; }
    if (theaterModal === "edit" && editingTheater) {
      updateTheaterMut.mutate({ id: editingTheater.id, input });
    } else {
      createTheaterMut.mutate(input);
    }
  }

  function openCreateScreen(theaterId: string) {
    setExpandedTheater(theaterId);
    setEditingScreen(null);
    setScreenForm(emptyScreenForm());
    setScreenErr("");
    setScreenModal("create");
  }

  function openEditScreen(sc: Screen) {
    setEditingScreen(sc);
    setScreenForm({
      name: sc.name,
      rows_count: String(Math.ceil(sc.capacity / (sc.seats?.length ? sc.seats.filter((s) => s.row === sc.seats[0]?.row).length : 1)) || 8),
      seats_per_row: String(sc.seats?.filter((s) => s.row === sc.seats[0]?.row).length || 12),
      vip_rows: sc.seats?.filter((s) => s.category === "vip").map((s) => s.row).filter((v, i, a) => a.indexOf(v) === i).join(", ") ?? "",
      premium_rows: sc.seats?.filter((s) => s.category === "premium").map((s) => s.row).filter((v, i, a) => a.indexOf(v) === i).join(", ") ?? "",
    });
    setScreenErr("");
    setScreenModal("edit");
  }

  function closeScreenModal() {
    setScreenModal(null);
    setScreenErr("");
  }

  function submitScreen() {
    setScreenErr("");
    const rows = parseInt(screenForm.rows_count);
    const spr = parseInt(screenForm.seats_per_row);
    if (!screenForm.name.trim()) { setScreenErr("Name is required"); return; }
    if (isNaN(rows) || rows < 1 || rows > 26) { setScreenErr("Rows must be 1–26"); return; }
    if (isNaN(spr) || spr < 1 || spr > 50) { setScreenErr("Seats per row must be 1–50"); return; }

    const input: ScreenInput = {
      name: screenForm.name.trim(),
      rows_count: rows,
      seats_per_row: spr,
      row_categories: parseRowCategories(screenForm.vip_rows, screenForm.premium_rows),
    };

    if (screenModal === "edit" && editingScreen && expandedTheater) {
      updateScreenMut.mutate({ theaterId: expandedTheater, screenId: editingScreen.id, input });
    } else if (expandedTheater) {
      createScreenMut.mutate({ theaterId: expandedTheater, input });
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────
  const theaterBusy = createTheaterMut.isPending || updateTheaterMut.isPending;
  const screenBusy = createScreenMut.isPending || updateScreenMut.isPending;

  const statusBadge = (status: string) => (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: "12px",
        fontSize: "0.72rem",
        fontWeight: 600,
        background: status === "active" ? "rgba(34,197,94,0.12)" : "rgba(148,163,184,0.15)",
        color: status === "active" ? "var(--success)" : "var(--text-dim)",
      }}
    >
      {status.toUpperCase()}
    </span>
  );

  return (
    <div>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1.5rem" }}>
        <div>
          <h1 style={{ fontSize: "1.25rem", fontWeight: 700, margin: 0 }}>Theaters</h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.82rem", margin: "0.25rem 0 0" }}>
            Manage theaters, screens, and seat layouts
          </p>
        </div>
        <button
          onClick={openCreateTheater}
          style={{
            display: "flex", alignItems: "center", gap: "0.4rem",
            padding: "0.5rem 1rem", borderRadius: "8px",
            background: "var(--accent)", color: "#fff",
            border: "none", cursor: "pointer", fontSize: "0.83rem", fontWeight: 600,
          }}
        >
          <Plus size={14} /> New Theater
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

      {/* Theater table */}
      {isLoading ? (
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>Loading…</p>
      ) : theaters.length === 0 ? (
        <div style={{ textAlign: "center", padding: "3rem", color: "var(--text-muted)", fontSize: "0.85rem" }}>
          No theaters yet. Create one to get started.
        </div>
      ) : (
        <div style={{ border: "1px solid var(--border)", borderRadius: "10px", overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "var(--surface-2)", borderBottom: "1px solid var(--border)" }}>
                {["Theater", "Location", "Status", "Actions"].map((h) => (
                  <th key={h} style={{ padding: "0.65rem 1rem", textAlign: "left", fontSize: "0.75rem", fontWeight: 600, color: "var(--text-muted)", letterSpacing: "0.04em" }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {theaters.map((t) => (
                <>
                  <tr
                    key={t.id}
                    style={{ borderBottom: expandedTheater === t.id ? "none" : "1px solid var(--border)", background: expandedTheater === t.id ? "var(--surface-2)" : "transparent" }}
                  >
                    <td style={{ padding: "0.75rem 1rem" }}>
                      <button
                        onClick={() => setExpandedTheater(expandedTheater === t.id ? null : t.id)}
                        style={{ display: "flex", alignItems: "center", gap: "0.4rem", background: "none", border: "none", cursor: "pointer", color: "var(--text)", fontWeight: 600, fontSize: "0.85rem" }}
                      >
                        {expandedTheater === t.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        {t.name}
                      </button>
                    </td>
                    <td style={{ padding: "0.75rem 1rem", color: "var(--text-muted)", fontSize: "0.83rem" }}>{t.location}</td>
                    <td style={{ padding: "0.75rem 1rem" }}>{statusBadge(t.status)}</td>
                    <td style={{ padding: "0.75rem 1rem" }}>
                      <div style={{ display: "flex", gap: "0.5rem" }}>
                        <button
                          title="Manage screens"
                          onClick={() => { setExpandedTheater(t.id); openCreateScreen(t.id); }}
                          style={{ padding: "4px 8px", borderRadius: "6px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", color: "var(--text-muted)", display: "flex", alignItems: "center", gap: "0.3rem", fontSize: "0.75rem" }}
                        >
                          <Monitor size={12} /> Screens
                        </button>
                        <button
                          title="Edit"
                          onClick={() => openEditTheater(t)}
                          style={{ padding: "4px 6px", borderRadius: "6px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", color: "var(--text-muted)" }}
                        >
                          <Pencil size={12} />
                        </button>
                        {t.status === "active" && (
                          <button
                            title="Disable"
                            onClick={() => setConfirmDisable(t)}
                            style={{ padding: "4px 6px", borderRadius: "6px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", color: "var(--danger)" }}
                          >
                            <Ban size={12} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>

                  {/* Expanded screens panel */}
                  {expandedTheater === t.id && (
                    <tr key={`${t.id}-screens`} style={{ borderBottom: "1px solid var(--border)" }}>
                      <td colSpan={4} style={{ padding: "0 1rem 1rem 2.5rem", background: "var(--surface-2)" }}>
                        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "0.5rem" }}>
                          <span style={{ fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)" }}>
                            SCREENS
                          </span>
                          <button
                            onClick={() => openCreateScreen(t.id)}
                            style={{
                              display: "flex", alignItems: "center", gap: "0.3rem",
                              padding: "3px 8px", borderRadius: "6px",
                              background: "var(--accent)", color: "#fff",
                              border: "none", cursor: "pointer", fontSize: "0.75rem",
                            }}
                          >
                            <Plus size={11} /> Add Screen
                          </button>
                        </div>

                        {screens.length === 0 ? (
                          <p style={{ fontSize: "0.78rem", color: "var(--text-dim)", margin: 0 }}>
                            No screens. Click Add Screen to create one.
                          </p>
                        ) : (
                          <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                            {screens.map((sc) => (
                              <div
                                key={sc.id}
                                style={{
                                  display: "flex", alignItems: "center", justifyContent: "space-between",
                                  padding: "0.5rem 0.75rem", borderRadius: "8px",
                                  border: "1px solid var(--border)", background: "var(--surface)",
                                }}
                              >
                                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                                  <Monitor size={13} style={{ color: "var(--text-muted)" }} />
                                  <div>
                                    <span style={{ fontWeight: 600, fontSize: "0.83rem" }}>{sc.name}</span>
                                    <span style={{ color: "var(--text-muted)", fontSize: "0.75rem", marginLeft: "0.5rem" }}>
                                      {sc.capacity} seats
                                    </span>
                                  </div>
                                  {statusBadge(sc.status)}
                                </div>
                                <div style={{ display: "flex", gap: "0.4rem" }}>
                                  <button
                                    onClick={() => openEditScreen(sc)}
                                    style={{ padding: "3px 6px", borderRadius: "5px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", color: "var(--text-muted)" }}
                                  >
                                    <Pencil size={11} />
                                  </button>
                                  {sc.status === "active" && (
                                    <button
                                      onClick={() => disableScreenMut.mutate({ theaterId: t.id, screenId: sc.id })}
                                      style={{ padding: "3px 6px", borderRadius: "5px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", color: "var(--danger)" }}
                                    >
                                      <Ban size={11} />
                                    </button>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Theater create/edit modal */}
      {theaterModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 50 }}>
          <div style={{ background: "var(--surface)", borderRadius: "12px", padding: "1.5rem", width: "420px", maxWidth: "90vw" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem" }}>
              <h2 style={{ margin: 0, fontSize: "1rem", fontWeight: 700 }}>
                {theaterModal === "edit" ? "Edit Theater" : "New Theater"}
              </h2>
              <button onClick={closeTheaterModal} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}>
                <X size={16} />
              </button>
            </div>

            {theaterErr && (
              <p style={{ color: "var(--danger)", fontSize: "0.8rem", margin: "0 0 0.75rem", padding: "0.5rem 0.75rem", background: "rgba(239,68,68,0.08)", borderRadius: "6px" }}>
                {theaterErr}
              </p>
            )}

            {[
              { label: "Name", key: "name" as const, placeholder: "Grand Cinema" },
              { label: "Location", key: "location" as const, placeholder: "123 Main St, City" },
            ].map(({ label, key, placeholder }) => (
              <div key={key} style={{ marginBottom: "1rem" }}>
                <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "0.3rem" }}>
                  {label}
                </label>
                <input
                  value={theaterForm[key]}
                  onChange={(e) => setTheaterForm((f) => ({ ...f, [key]: e.target.value }))}
                  placeholder={placeholder}
                  style={{ width: "100%", padding: "0.5rem 0.75rem", borderRadius: "7px", border: "1px solid var(--border)", background: "var(--surface-2)", color: "var(--text)", fontSize: "0.85rem", boxSizing: "border-box" }}
                />
              </div>
            ))}

            <div style={{ display: "flex", gap: "0.75rem", justifyContent: "flex-end", marginTop: "1.25rem" }}>
              <button onClick={closeTheaterModal} style={{ padding: "0.5rem 1rem", borderRadius: "7px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", fontSize: "0.83rem" }}>
                Cancel
              </button>
              <button
                onClick={submitTheater}
                disabled={theaterBusy}
                style={{ padding: "0.5rem 1rem", borderRadius: "7px", background: "var(--accent)", color: "#fff", border: "none", cursor: "pointer", fontSize: "0.83rem", fontWeight: 600, opacity: theaterBusy ? 0.6 : 1 }}
              >
                {theaterBusy ? "Saving…" : theaterModal === "edit" ? "Save" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Disable-theater confirmation dialog */}
      {confirmDisable && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 60 }}>
          <div style={{ background: "var(--surface)", borderRadius: "12px", padding: "1.5rem", width: "380px", maxWidth: "90vw" }}>
            <h2 style={{ margin: "0 0 0.75rem", fontSize: "1rem", fontWeight: 700 }}>Disable theater?</h2>
            <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", margin: "0 0 0.5rem" }}>
              <strong style={{ color: "var(--text)" }}>{confirmDisable.name}</strong> will be marked as disabled.
            </p>
            <p style={{ fontSize: "0.82rem", color: "var(--danger)", background: "rgba(239,68,68,0.08)", borderRadius: "6px", padding: "0.5rem 0.75rem", margin: "0 0 1.25rem" }}>
              Any active screens under this theater will remain active in the database. Disable them separately if needed.
            </p>
            <div style={{ display: "flex", gap: "0.75rem", justifyContent: "flex-end" }}>
              <button
                onClick={() => setConfirmDisable(null)}
                style={{ padding: "0.5rem 1rem", borderRadius: "7px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", fontSize: "0.83rem" }}
              >
                Cancel
              </button>
              <button
                onClick={() => { disableTheaterMut.mutate(confirmDisable.id); setConfirmDisable(null); }}
                style={{ padding: "0.5rem 1rem", borderRadius: "7px", background: "var(--danger)", color: "#fff", border: "none", cursor: "pointer", fontSize: "0.83rem", fontWeight: 600 }}
              >
                Disable
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Screen create/edit modal */}
      {screenModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 50 }}>
          <div style={{ background: "var(--surface)", borderRadius: "12px", padding: "1.5rem", width: "460px", maxWidth: "90vw" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem" }}>
              <h2 style={{ margin: 0, fontSize: "1rem", fontWeight: 700 }}>
                {screenModal === "edit" ? "Edit Screen" : "New Screen"}
              </h2>
              <button onClick={closeScreenModal} style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)" }}>
                <X size={16} />
              </button>
            </div>

            {screenErr && (
              <p style={{ color: "var(--danger)", fontSize: "0.8rem", margin: "0 0 0.75rem", padding: "0.5rem 0.75rem", background: "rgba(239,68,68,0.08)", borderRadius: "6px" }}>
                {screenErr}
              </p>
            )}

            <div style={{ marginBottom: "1rem" }}>
              <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "0.3rem" }}>Screen Name</label>
              <input
                value={screenForm.name}
                onChange={(e) => setScreenForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="Screen 1"
                style={{ width: "100%", padding: "0.5rem 0.75rem", borderRadius: "7px", border: "1px solid var(--border)", background: "var(--surface-2)", color: "var(--text)", fontSize: "0.85rem", boxSizing: "border-box" }}
              />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", marginBottom: "1rem" }}>
              {[
                { label: "Rows (A-Z)", key: "rows_count" as const, placeholder: "8" },
                { label: "Seats per row", key: "seats_per_row" as const, placeholder: "12" },
              ].map(({ label, key, placeholder }) => (
                <div key={key}>
                  <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "0.3rem" }}>{label}</label>
                  <input
                    type="number"
                    value={screenForm[key]}
                    onChange={(e) => setScreenForm((f) => ({ ...f, [key]: e.target.value }))}
                    placeholder={placeholder}
                    style={{ width: "100%", padding: "0.5rem 0.75rem", borderRadius: "7px", border: "1px solid var(--border)", background: "var(--surface-2)", color: "var(--text)", fontSize: "0.85rem", boxSizing: "border-box" }}
                  />
                </div>
              ))}
            </div>

            <div style={{ background: "var(--surface-2)", borderRadius: "8px", padding: "0.75rem", marginBottom: "1rem" }}>
              <p style={{ fontSize: "0.75rem", fontWeight: 600, color: "var(--text-muted)", margin: "0 0 0.5rem" }}>
                SEAT CATEGORIES — enter row letters, comma-separated (e.g. A, B)
              </p>
              {[
                { label: "VIP rows", key: "vip_rows" as const, placeholder: "A, B" },
                { label: "Premium rows", key: "premium_rows" as const, placeholder: "C, D" },
              ].map(({ label, key, placeholder }) => (
                <div key={key} style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.4rem" }}>
                  <label style={{ fontSize: "0.78rem", color: "var(--text-muted)", width: "90px", flexShrink: 0 }}>{label}</label>
                  <input
                    value={screenForm[key]}
                    onChange={(e) => setScreenForm((f) => ({ ...f, [key]: e.target.value }))}
                    placeholder={placeholder}
                    style={{ flex: 1, padding: "0.35rem 0.6rem", borderRadius: "6px", border: "1px solid var(--border)", background: "var(--surface)", color: "var(--text)", fontSize: "0.82rem" }}
                  />
                </div>
              ))}
              <p style={{ fontSize: "0.72rem", color: "var(--text-dim)", margin: "0.4rem 0 0" }}>
                Remaining rows default to Standard.
              </p>
            </div>

            {screenForm.rows_count && screenForm.seats_per_row && (
              <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "1rem" }}>
                Total capacity: {(parseInt(screenForm.rows_count) || 0) * (parseInt(screenForm.seats_per_row) || 0)} seats
              </p>
            )}

            <div style={{ display: "flex", gap: "0.75rem", justifyContent: "flex-end" }}>
              <button onClick={closeScreenModal} style={{ padding: "0.5rem 1rem", borderRadius: "7px", border: "1px solid var(--border)", background: "transparent", cursor: "pointer", fontSize: "0.83rem" }}>
                Cancel
              </button>
              <button
                onClick={submitScreen}
                disabled={screenBusy}
                style={{ padding: "0.5rem 1rem", borderRadius: "7px", background: "var(--accent)", color: "#fff", border: "none", cursor: "pointer", fontSize: "0.83rem", fontWeight: 600, opacity: screenBusy ? 0.6 : 1 }}
              >
                {screenBusy ? "Saving…" : screenModal === "edit" ? "Save" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
