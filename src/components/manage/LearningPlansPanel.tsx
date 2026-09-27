"use client";
/**
 * Learning plans (v2 of the assignments panel — docs/SPEC-assignments-v2.md).
 *
 * The editor is three columns: the module TREE on the left (tick V at any level
 * selects everything under it), the SELECTED items in the centre (order,
 * per-item priority + note), and the RECIPIENTS on the right (whole org, or any
 * mix of groups and specific people) with title, instructions, due date and the
 * plan's overall priority. Existing plans can be edited, archived/restored and
 * opened into a users × items progress matrix.
 *
 * The catalogue tree and all progress come from the server (/api/org/catalog,
 * /api/org/assignments); every value is re-validated there. Personal plans are
 * set per learner on the student page, not here.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import {
  ClipboardList, Plus, Trash2, Clock, Loader2, X, Pencil, Archive, ArchiveRestore, BarChart3, Users, Search, Save,
} from "lucide-react";
import { ModuleTree, indexLeaves } from "@/components/plans/ModuleTree";
import { PlanItemsEditor } from "@/components/plans/PlanItemsEditor";
import { applyToggle, capNotice } from "@/lib/plans/selection";
import { PlanProgressMatrix } from "@/components/plans/PlanProgressMatrix";
import { describeNotifyOutcome } from "@/lib/notifications/types";
import {
  PLAN_LIMITS, PRIORITY_LABEL, formatDueDate, itemKey,
  type Audience, type CatalogNode, type PlanItem, type Priority, type StaffPlan,
} from "@/lib/plans/types";

export interface RosterMember {
  user_id: string;
  display_name?: string | null;
  handle?: string | null;
  status: string;
  role: string;
}
interface GroupLite { id: string; name: string; member_count: number }

interface Draft {
  id?: string;
  title: string;
  instructions: string;
  due: string;
  priority: Priority;
  audience: Audience;
  groupIds: string[];
  userIds: string[];
  items: PlanItem[];
  /** "Also email recipients" — per save, always starts OFF (in-app notifications are always sent). */
  notifyEmail: boolean;
}
const EMPTY: Draft = { title: "", instructions: "", due: "", priority: 2, audience: "org", groupIds: [], userIds: [], items: [], notifyEmail: false };

export const memberName = (m: RosterMember) => m.display_name || m.handle || m.user_id.slice(0, 8);

function dueLabel(iso: string | null): { text: string; past: boolean } {
  if (!iso) return { text: "no due date", past: false };
  return { text: formatDueDate(iso), past: Date.parse(iso) < Date.now() };
}

export function PriorityChip({ p }: { p: Priority }) {
  if (p === 2) return null;
  return (
    <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider ${
      p === 1 ? "border-neon-amber/40 bg-neon-amber/10 text-neon-amber" : "border-border bg-bg text-slate-500"
    }`}>{PRIORITY_LABEL[p]}</span>
  );
}

export function LearningPlansPanel({ members, groupsRev = 0 }: { members: RosterMember[]; groupsRev?: number }) {
  const [plans, setPlans] = useState<StaffPlan[] | null>(null);
  const [groups, setGroups] = useState<GroupLite[]>([]);
  const [tree, setTree] = useState<CatalogNode[] | null>(null);
  const [treeError, setTreeError] = useState(false);
  const [capMsg, setCapMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [busy, setBusy] = useState(false);
  const [showArchived, setShowArchived] = useState(false);
  const [matrixFor, setMatrixFor] = useState<string | null>(null);
  const [peopleQ, setPeopleQ] = useState("");

  const load = useCallback(async () => {
    const res = await fetch("/api/org/assignments");
    if (!res.ok) { setPlans([]); setError((await res.json().catch(() => ({})))?.error ?? "Could not load learning plans."); return; }
    const d = await res.json();
    setPlans(d.plans ?? []);
    setGroups(d.groups ?? []);
  }, []);
  useEffect(() => { load(); }, [load, groupsRev]);

  const leaves = useMemo(() => indexLeaves(tree ?? []), [tree]);
  const selected = useMemo(() => new Set((draft?.items ?? []).map(itemKey)), [draft?.items]);
  const active = useMemo(() => members.filter(m => m.status === "active").sort((a, b) => memberName(a).localeCompare(memberName(b))), [members]);
  const nameOf = useMemo(() => new Map(members.map(m => [m.user_id, memberName(m)])), [members]);
  const groupName = useMemo(() => new Map(groups.map(g => [g.id, g.name])), [groups]);

  async function loadTree() {
    setTreeError(false);
    const res = await fetch("/api/org/catalog").catch(() => null);
    if (res?.ok) setTree((await res.json()).tree ?? []);
    else setTreeError(true);
  }

  async function openEditor(d: Draft) {
    setError(null); setNotice(null); setPeopleQ(""); setCapMsg(null);
    setDraft(d);
    if (!tree) await loadTree();
  }

  function toggleKeys(keys: string[], sel: boolean) {
    if (!draft) return;
    const r = applyToggle(draft.items, keys, sel, leaves);
    setCapMsg(capNotice(r.dropped));
    setDraft({ ...draft, items: r.items });
  }

  function editPlan(p: StaffPlan) {
    openEditor({
      id: p.id,
      title: p.title,
      instructions: p.instructions ?? "",
      due: p.due_at ? p.due_at.slice(0, 10) : "",
      priority: p.priority,
      audience: p.audience,
      groupIds: p.targets.group_ids,
      userIds: p.targets.user_ids,
      items: p.items.map(({ kind, id, priority, note }) => ({ kind, id, ...(priority ? { priority } : {}), ...(note ? { note } : {}) })),
      notifyEmail: false,
    });
  }

  const toggleId = (list: string[], id: string) => (list.includes(id) ? list.filter(x => x !== id) : [...list, id]);

  async function save() {
    if (!draft) return;
    if (!draft.title.trim()) { setError("Give the plan a title."); return; }
    if (draft.items.length === 0) { setError("Tick at least one module in the tree."); return; }
    if (draft.audience === "targeted" && draft.groupIds.length + draft.userIds.length === 0) {
      setError("Choose at least one group or person — or assign it to the whole organisation."); return;
    }
    setBusy(true); setError(null);
    const payload = {
      ...(draft.id ? { id: draft.id } : {}),
      title: draft.title.trim(),
      instructions: draft.instructions.trim(),
      due_at: draft.due || null,
      priority: draft.priority,
      audience: draft.audience,
      targets: { group_ids: draft.groupIds, user_ids: draft.userIds },
      items: draft.items,
      notify_email: draft.notifyEmail,
    };
    const res = await fetch("/api/org/assignments", {
      method: draft.id ? "PATCH" : "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    });
    setBusy(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Could not save the plan."); return; }
    // The real outcome from the API: "3 learners notified · 3 emailed", or why emails were skipped.
    const outcome = describeNotifyOutcome(await res.json().catch(() => null));
    setNotice((draft.id ? "Plan updated." : "Plan assigned.") + (outcome ? ` ${outcome}.` : ""));
    setDraft(null);
    await load();
  }

  async function setArchived(p: StaffPlan, archived: boolean) {
    const res = await fetch("/api/org/assignments", {
      method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: p.id, archived }),
    });
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Could not update the plan."); return; }
    setNotice(archived ? `“${p.title}” archived — learners no longer see it.` : `“${p.title}” restored.`);
    await load();
  }

  async function remove(p: StaffPlan) {
    if (!confirm(`Delete “${p.title}” permanently? Learners will no longer see it. (Archive keeps it for your records.)`)) return;
    const res = await fetch(`/api/org/assignments?id=${encodeURIComponent(p.id)}`, { method: "DELETE" });
    if (!res.ok) { setError("Could not delete the plan."); return; }
    await load();
  }

  if (plans === null) return null;

  const visible = plans.filter(p => showArchived || !p.archived_at);
  const archivedCount = plans.filter(p => p.archived_at).length;
  const people = peopleQ.trim()
    ? active.filter(m => memberName(m).toLowerCase().includes(peopleQ.trim().toLowerCase()) || (m.handle ?? "").toLowerCase().includes(peopleQ.trim().toLowerCase()))
    : active;

  function audienceText(p: StaffPlan): string {
    if (p.audience === "org") return "Whole organisation";
    const parts = p.targets.group_ids.map(g => groupName.get(g) ?? "group");
    const u = p.targets.user_ids;
    if (u.length === 1) parts.push(nameOf.get(u[0]) ?? "1 person");
    else if (u.length > 1) parts.push(`${u.length} people`);
    return parts.join(" · ") || "No recipients";
  }

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-sm font-bold text-white">
          <ClipboardList className="h-4 w-4 text-cyber-300" /> Learning plans
        </h2>
        <div className="flex items-center gap-2">
          {archivedCount > 0 && (
            <button onClick={() => setShowArchived(v => !v)} className="text-[11px] text-slate-400 transition hover:text-white">
              {showArchived ? "Hide archived" : `Show archived (${archivedCount})`}
            </button>
          )}
          <Button variant="outline" size="sm" onClick={() => (draft ? setDraft(null) : openEditor({ ...EMPTY }))}>
            {draft ? <X className="mr-1.5 h-4 w-4" /> : <Plus className="mr-1.5 h-4 w-4" />}
            {draft ? "Cancel" : "New plan"}
          </Button>
        </div>
      </div>
      <p className="mt-1 text-xs text-slate-400">
        Prioritise modules and practice for the whole organisation, a group such as “Tier-1 analysts”, or specific people.
        Personal priorities for one learner are set on their student page.
      </p>

      {error && <p className="mt-2 text-xs text-severity-high">{error}</p>}
      {notice && !error && <p className="mt-2 text-xs text-neon-green">{notice}</p>}

      {draft && (
        <div className="mt-4 rounded-lg border border-border bg-bg-elevated p-3">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">{draft.id ? "Edit plan" : "New plan"}</p>
          <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)_minmax(0,0.95fr)]">
            {/* Left — module tree */}
            <div className="flex min-w-0 flex-col">
              <p className="mb-1.5 text-[10px] uppercase tracking-wider text-slate-500">Modules</p>
              {tree ? (
                <ModuleTree tree={tree} selected={selected} onToggle={toggleKeys} className="h-[420px]" />
              ) : treeError ? (
                <div className="flex h-[420px] flex-col items-center justify-center gap-2 rounded-lg border border-severity-high/40 bg-bg px-4 text-center text-xs text-severity-high">
                  Could not load the module catalogue.
                  <Button variant="outline" size="sm" onClick={loadTree}>Retry</Button>
                </div>
              ) : (
                <div className="flex h-[420px] items-center justify-center rounded-lg border border-border bg-bg text-xs text-slate-500">
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading modules…
                </div>
              )}
            </div>

            {/* Centre — selected items */}
            <div className="flex min-w-0 flex-col">
              <p className="mb-1.5 flex items-center justify-between text-[10px] uppercase tracking-wider text-slate-500">
                <span>Selected ({draft.items.length}/{PLAN_LIMITS.items})</span>
                {draft.items.length > 0 && (
                  <button onClick={() => { setCapMsg(null); setDraft(d => d && { ...d, items: [] }); }} className="normal-case tracking-normal text-slate-500 hover:text-slate-200">clear</button>
                )}
              </p>
              {capMsg && <p className="mb-1.5 rounded border border-neon-amber/40 bg-neon-amber/10 px-2 py-1 text-[11px] text-neon-amber">{capMsg}</p>}
              <PlanItemsEditor
                items={draft.items}
                leaves={leaves}
                onChange={items => { setCapMsg(null); setDraft(d => d && { ...d, items }); }}
                className={capMsg ? "h-[380px]" : "h-[420px]"}
              />
            </div>

            {/* Right — details + recipients */}
            <div className="flex min-w-0 flex-col gap-2">
              <p className="text-[10px] uppercase tracking-wider text-slate-500">Details</p>
              <input
                value={draft.title} onChange={e => setDraft(d => d && { ...d, title: e.target.value })} maxLength={PLAN_LIMITS.title}
                placeholder="Plan title (e.g. Tier-1 onboarding)"
                className="rounded-md border border-border bg-bg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none"
              />
              <textarea
                value={draft.instructions} onChange={e => setDraft(d => d && { ...d, instructions: e.target.value })} maxLength={PLAN_LIMITS.instructions}
                placeholder="Instructions for learners (optional)" rows={3}
                className="resize-none rounded-md border border-border bg-bg px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none"
              />
              <div className="flex gap-2">
                <label className="flex flex-1 items-center gap-2 rounded-md border border-border bg-bg px-2.5 py-1.5 text-xs text-slate-400">
                  <Clock className="h-3.5 w-3.5 shrink-0" /> due
                  <input type="date" value={draft.due} onChange={e => setDraft(d => d && { ...d, due: e.target.value })} className="min-w-0 flex-1 bg-transparent text-slate-100 focus:outline-none" />
                </label>
                <select
                  value={draft.priority} onChange={e => setDraft(d => d && { ...d, priority: Number(e.target.value) as Priority })} aria-label="Plan priority"
                  className="rounded-md border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none"
                >
                  {([1, 2, 3] as Priority[]).map(p => <option key={p} value={p}>{PRIORITY_LABEL[p]} priority</option>)}
                </select>
              </div>

              <p className="mt-1 text-[10px] uppercase tracking-wider text-slate-500">Recipients</p>
              <div className="flex rounded-md border border-border bg-bg p-0.5 text-xs">
                {(["org", "targeted"] as Audience[]).map(a => (
                  <button key={a} onClick={() => setDraft(d => d && { ...d, audience: a })}
                    className={`flex-1 rounded px-2 py-1 transition ${draft.audience === a ? "bg-cyber-500/20 font-semibold text-cyber-200" : "text-slate-400 hover:text-white"}`}>
                    {a === "org" ? "Whole org" : "Groups & people"}
                  </button>
                ))}
              </div>

              {draft.audience === "targeted" && (
                <div className="flex min-h-0 flex-1 flex-col gap-2">
                  <div className="rounded-md border border-border bg-bg p-1.5">
                    <p className="px-1 pb-1 text-[10px] uppercase tracking-wider text-slate-500">Groups</p>
                    {groups.length === 0 ? (
                      <p className="px-1 pb-1 text-[11px] text-slate-500">No groups yet — create one in the Groups panel.</p>
                    ) : (
                      <div className="max-h-28 space-y-0.5 overflow-y-auto">
                        {groups.map(g => (
                          <label key={g.id} className="flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-[12px] text-slate-300 hover:bg-white/5">
                            <input type="checkbox" checked={draft.groupIds.includes(g.id)} onChange={() => setDraft(d => d && { ...d, groupIds: toggleId(d.groupIds, g.id) })} className="accent-cyan-500" />
                            <span className="min-w-0 flex-1 truncate">{g.name}</span>
                            <span className="font-mono text-[10px] text-slate-500">{g.member_count}</span>
                          </label>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="flex min-h-0 flex-1 flex-col rounded-md border border-border bg-bg p-1.5">
                    <div className="flex items-center gap-1.5 px-1 pb-1">
                      <span className="text-[10px] uppercase tracking-wider text-slate-500">People</span>
                      <span className="font-mono text-[10px] text-slate-600">{draft.userIds.length ? `${draft.userIds.length} chosen` : ""}</span>
                      <Search className="ml-auto h-3 w-3 text-slate-500" />
                      <input value={peopleQ} onChange={e => setPeopleQ(e.target.value)} placeholder="find…"
                        className="w-20 bg-transparent text-[11px] text-slate-200 placeholder:text-slate-600 focus:outline-none" />
                    </div>
                    <div className="max-h-40 space-y-0.5 overflow-y-auto">
                      {people.length === 0 && <p className="px-1 text-[11px] text-slate-500">No matching learners.</p>}
                      {people.map(m => (
                        <label key={m.user_id} className="flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-[12px] text-slate-300 hover:bg-white/5">
                          <input type="checkbox" checked={draft.userIds.includes(m.user_id)} onChange={() => setDraft(d => d && { ...d, userIds: toggleId(d.userIds, m.user_id) })} className="accent-cyan-500" />
                          <span className="min-w-0 flex-1 truncate">{memberName(m)}</span>
                          {m.role !== "student" && <span className="text-[9px] uppercase tracking-wider text-slate-500">{m.role.replace("_", " ")}</span>}
                        </label>
                      ))}
                    </div>
                  </div>
                </div>
              )}
              {draft.audience === "org" && (
                <p className="flex items-center gap-1.5 rounded-md border border-border bg-bg px-2.5 py-2 text-[11px] text-slate-400">
                  <Users className="h-3.5 w-3.5 shrink-0" /> Every student in the organisation, including those who join later.
                </p>
              )}

              <label
                className="mt-auto flex cursor-pointer items-start gap-2 rounded-md border border-border bg-bg px-2.5 py-2 text-[11px] text-slate-300"
                title="Learners always get an in-app notification. Tick to also send each of them one short email."
              >
                <input type="checkbox" checked={draft.notifyEmail} onChange={e => setDraft(d => d && { ...d, notifyEmail: e.target.checked })} className="mt-0.5 accent-cyan-500" />
                <span>
                  Also email recipients
                  <span className="block text-[10px] text-slate-500">
                    {draft.id ? "Only people newly receiving it, or told about new items." : "Everyone this plan reaches gets an in-app notification either way."}
                  </span>
                </span>
              </label>
              <Button variant="primary" size="sm" disabled={busy} onClick={save}>
                {busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Save className="mr-1.5 h-4 w-4" />}
                {draft.id ? "Save changes" : "Assign plan"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {visible.length === 0 ? (
        <p className="mt-3 text-sm text-slate-400">No learning plans yet. Create one so learners know what to prioritise.</p>
      ) : (
        <div className="mt-4 space-y-2">
          {visible.map(p => {
            const due = dueLabel(p.due_at);
            const total = p.progress.length;
            const pct = total > 0 ? Math.round((p.completed / total) * 100) : 0;
            const archived = Boolean(p.archived_at);
            return (
              <div key={p.id} className={`rounded-lg border border-border bg-bg-elevated px-3 py-2.5 ${archived ? "opacity-60" : ""}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="truncate text-sm font-medium text-slate-100">{p.title}</p>
                      <PriorityChip p={p.priority} />
                      {archived && <span className="rounded border border-border px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-slate-500">archived</span>}
                    </div>
                    <p className="mt-0.5 flex items-center gap-1 text-[11px] text-slate-400">
                      <Users className="h-3 w-3" /> {audienceText(p)} · {p.items.length} item{p.items.length === 1 ? "" : "s"}
                    </p>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      {p.items.slice(0, 6).map(it => (
                        <span key={`${it.kind}:${it.id}`} className="inline-flex max-w-[220px] items-center gap-1 truncate rounded border border-border bg-bg px-1.5 py-0.5 text-[10px] text-slate-400">
                          {it.priority === 1 && <span className="text-neon-amber">!</span>}{it.title}
                        </span>
                      ))}
                      {p.items.length > 6 && <span className="px-1 py-0.5 text-[10px] text-slate-500">+{p.items.length - 6} more</span>}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <span className={`mr-1 inline-flex items-center gap-1 text-[11px] ${due.past && !archived ? "text-neon-amber" : "text-slate-400"}`}>
                      <Clock className="h-3 w-3" /> {due.text}
                    </span>
                    <button onClick={() => setMatrixFor(v => (v === p.id ? null : p.id))} aria-label="Progress" title="Progress"
                      className={`rounded p-1 transition hover:bg-white/5 ${matrixFor === p.id ? "text-cyber-300" : "text-slate-500 hover:text-slate-200"}`}>
                      <BarChart3 className="h-3.5 w-3.5" />
                    </button>
                    <button onClick={() => editPlan(p)} aria-label="Edit plan" title="Edit"
                      className="rounded p-1 text-slate-500 transition hover:bg-white/5 hover:text-slate-200">
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                    <button onClick={() => setArchived(p, !archived)} aria-label={archived ? "Restore plan" : "Archive plan"} title={archived ? "Restore" : "Archive"}
                      className="rounded p-1 text-slate-500 transition hover:bg-white/5 hover:text-slate-200">
                      {archived ? <ArchiveRestore className="h-3.5 w-3.5" /> : <Archive className="h-3.5 w-3.5" />}
                    </button>
                    <button onClick={() => remove(p)} aria-label="Delete plan" title="Delete"
                      className="rounded p-1 text-slate-500 transition hover:bg-severity-high/10 hover:text-severity-high">
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
                {total > 0 && (
                  <button onClick={() => setMatrixFor(v => (v === p.id ? null : p.id))} className="mt-2 flex w-full items-center gap-2 text-left">
                    <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-bg">
                      <span className="block h-full bg-cyber-500" style={{ width: `${pct}%` }} />
                    </span>
                    <span className="shrink-0 font-mono text-[10px] text-slate-400">{p.completed}/{total} finished all</span>
                  </button>
                )}
                {matrixFor === p.id && (
                  <div className="mt-3 border-t border-border/60 pt-3">
                    <PlanProgressMatrix plan={p} />
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
