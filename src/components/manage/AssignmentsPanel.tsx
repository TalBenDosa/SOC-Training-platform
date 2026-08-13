"use client";
/**
 * Assignments panel for the org-admin dashboard. Wires the EXISTING
 * /api/org/assignments routes (create/list/delete, due dates, cohort completion)
 * into the Manage page — the API shipped in 0021 but was never rendered here.
 *
 * Staff (org_admin/instructor) get a create form + cohort completion + delete.
 * The tenant boundary is enforced server-side (every query pinned to the JWT
 * org); this component only presents.
 */
import { useEffect, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ClipboardList, Plus, Trash2, Clock, Loader2, Search, X, Check } from "lucide-react";

interface Item { kind: "room" | "scenario"; id: string }
interface CatalogItem extends Item { title: string; group: string; difficulty: string }
interface AssignmentRow {
  id: string;
  title: string;
  instructions: string | null;
  items: Item[];
  due_at: string | null;
  created_at: string;
  item_titles: { kind: string; id: string; title: string }[];
  cohort?: { completed: number; total: number };
}

function dueLabel(iso: string | null): { text: string; overdue: boolean } {
  if (!iso) return { text: "no due date", overdue: false };
  const d = new Date(iso);
  const overdue = d.getTime() < Date.now();
  return { text: d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }), overdue };
}

export function AssignmentsPanel() {
  const [rows, setRows] = useState<AssignmentRow[] | null>(null);
  const [isStaff, setIsStaff] = useState(false);
  const [catalog, setCatalog] = useState<CatalogItem[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [due, setDue] = useState("");
  const [picked, setPicked] = useState<Item[]>([]);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    const res = await fetch("/api/org/assignments");
    if (!res.ok) { setRows([]); return; }
    const d = await res.json();
    setRows(d.assignments ?? []);
    setIsStaff(Boolean(d.is_staff));
    setCatalog(d.catalog ?? []);
  }
  useEffect(() => { load(); }, []);

  const isPicked = (it: Item) => picked.some(x => x.kind === it.kind && x.id === it.id);
  function toggle(it: CatalogItem) {
    setPicked(p => isPicked(it) ? p.filter(x => !(x.kind === it.kind && x.id === it.id)) : [...p, { kind: it.kind, id: it.id }]);
  }

  async function create() {
    if (!title.trim() || picked.length === 0) { setError("Give it a title and pick at least one item."); return; }
    setBusy(true); setError(null);
    const res = await fetch("/api/org/assignments", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: title.trim(), items: picked, due_at: due || null }),
    });
    setBusy(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Could not create."); return; }
    setTitle(""); setDue(""); setPicked([]); setQ(""); setOpen(false);
    await load();
  }

  async function remove(id: string) {
    if (!confirm("Delete this assignment? Students will no longer see it.")) return;
    const res = await fetch(`/api/org/assignments?id=${encodeURIComponent(id)}`, { method: "DELETE" });
    if (res.ok) await load();
    else setError("Could not delete.");
  }

  if (rows === null) return null;
  // Students see their own assigned work elsewhere (AssignedWork); this panel is
  // the STAFF surface. Hide entirely for non-staff with nothing to manage.
  if (!isStaff && rows.length === 0) return null;

  const filtered = (q.trim()
    ? catalog.filter(c => c.title.toLowerCase().includes(q.toLowerCase()) || c.group.toLowerCase().includes(q.toLowerCase()))
    : catalog
  ).slice(0, 40);

  return (
    <Card>
      <div className="flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-sm font-bold text-white">
          <ClipboardList className="h-4 w-4 text-cyber-300" /> Assignments
        </h2>
        {isStaff && (
          <Button variant="outline" size="sm" onClick={() => setOpen(v => !v)}>
            {open ? <X className="mr-1.5 h-4 w-4" /> : <Plus className="mr-1.5 h-4 w-4" />}
            {open ? "Cancel" : "New assignment"}
          </Button>
        )}
      </div>

      {error && <p className="mt-2 text-xs text-severity-high">{error}</p>}

      {open && (
        <div className="mt-4 space-y-3 rounded-lg border border-border bg-bg-elevated p-3">
          <div className="flex flex-wrap gap-2">
            <input
              value={title} onChange={e => setTitle(e.target.value)} placeholder="Assignment title (e.g. Week 3 — SIEM triage)"
              className="min-w-[220px] flex-1 rounded-md border border-border bg-bg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none"
            />
            <label className="flex items-center gap-2 rounded-md border border-border bg-bg px-3 py-2 text-xs text-slate-400">
              <Clock className="h-3.5 w-3.5" /> due
              <input type="date" value={due} onChange={e => setDue(e.target.value)} className="bg-transparent text-slate-100 focus:outline-none" />
            </label>
          </div>

          {picked.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {picked.map(p => {
                const c = catalog.find(x => x.kind === p.kind && x.id === p.id);
                return (
                  <span key={`${p.kind}:${p.id}`} className="inline-flex items-center gap-1 rounded-full border border-cyber-500/40 bg-cyber-500/10 px-2 py-0.5 text-[11px] text-cyber-200">
                    {c?.title ?? p.id}
                    <button onClick={() => c && toggle(c)} aria-label="remove"><X className="h-3 w-3" /></button>
                  </span>
                );
              })}
            </div>
          )}

          <div className="flex items-center gap-2 rounded-md border border-border bg-bg px-2.5 py-1.5">
            <Search className="h-3.5 w-3.5 shrink-0 text-slate-500" />
            <input
              value={q} onChange={e => setQ(e.target.value)} placeholder="Search rooms and scenarios…"
              className="flex-1 bg-transparent text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none"
            />
          </div>
          <div className="max-h-48 space-y-0.5 overflow-y-auto">
            {filtered.map(c => (
              <button
                key={`${c.kind}:${c.id}`} onClick={() => toggle(c)}
                className={`flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-[12px] transition hover:bg-white/5 ${isPicked(c) ? "text-cyber-300" : "text-slate-300"}`}
              >
                <span className="w-3.5 shrink-0">{isPicked(c) ? <Check className="h-3.5 w-3.5" /> : null}</span>
                <span className="min-w-0 flex-1 truncate">{c.title}</span>
                <span className="shrink-0 text-[10px] uppercase tracking-wider text-slate-500">{c.kind === "scenario" ? "scenario" : c.group}</span>
              </button>
            ))}
          </div>

          <div className="flex justify-end">
            <Button variant="primary" size="sm" disabled={busy} onClick={create}>
              {busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Plus className="mr-1.5 h-4 w-4" />}
              Assign to class
            </Button>
          </div>
        </div>
      )}

      {rows.length === 0 ? (
        <p className="mt-3 text-sm text-slate-400">No assignments yet. Set one so students know what to work on.</p>
      ) : (
        <div className="mt-4 space-y-2">
          {rows.map(a => {
            const due = dueLabel(a.due_at);
            const done = a.cohort?.completed ?? 0;
            const total = a.cohort?.total ?? 0;
            const pct = total > 0 ? Math.round((done / total) * 100) : 0;
            return (
              <div key={a.id} className="rounded-lg border border-border bg-bg-elevated px-3 py-2.5">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-slate-100">{a.title}</p>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {a.item_titles.map(it => (
                        <span key={`${it.kind}:${it.id}`} className="inline-flex max-w-[220px] items-center gap-1 truncate rounded border border-border bg-bg px-1.5 py-0.5 text-[10px] text-slate-400">
                          {it.title}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <span className={`inline-flex items-center gap-1 text-[11px] ${due.overdue ? "text-neon-amber" : "text-slate-400"}`}>
                      <Clock className="h-3 w-3" /> {due.text}
                    </span>
                    {isStaff && (
                      <button onClick={() => remove(a.id)} aria-label="Delete assignment" title="Delete"
                        className="rounded p-1 text-slate-500 transition hover:bg-severity-high/10 hover:text-severity-high">
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                </div>
                {isStaff && total > 0 && (
                  <div className="mt-2 flex items-center gap-2">
                    <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-bg">
                      <span className="block h-full bg-cyber-500" style={{ width: `${pct}%` }} />
                    </span>
                    <span className="shrink-0 font-mono text-[10px] text-slate-400">{done}/{total} finished all</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}
