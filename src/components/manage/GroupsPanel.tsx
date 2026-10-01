"use client";
/**
 * Groups — named cohorts inside the org ("Tier-1 analysts", "Night shift") that
 * learning plans can target (migration 0075). Create, rename, delete, and pick
 * members from the roster. Everything is validated and org-pinned server-side
 * by /api/org/groups; this component only presents.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchOrError } from "@/lib/http/safeFetch";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { UsersRound, Plus, Trash2, Loader2, X, ChevronRight, Search, Save, Pencil } from "lucide-react";
import { PLAN_LIMITS, type GroupRow } from "@/lib/plans/types";
import { memberName, type RosterMember } from "@/components/manage/LearningPlansPanel";

export function GroupsPanel({ members, onChanged }: { members: RosterMember[]; onChanged?: () => void }) {
  const [groups, setGroups] = useState<GroupRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [busy, setBusy] = useState(false);

  // One group open at a time for editing its name + members.
  const [openId, setOpenId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editMembers, setEditMembers] = useState<string[]>([]);
  const [q, setQ] = useState("");

  const load = useCallback(async () => {
    const res = await fetchOrError("/api/org/groups");
    if (!res.ok) { setGroups([]); setError((await res.json().catch(() => ({})))?.error ?? "Could not load groups."); return; }
    setGroups((await res.json()).groups ?? []);
  }, []);
  useEffect(() => { load(); }, [load]);

  const roster = useMemo(() => [...members].filter(m => m.status === "active").sort((a, b) => memberName(a).localeCompare(memberName(b))), [members]);
  const nameOf = useMemo(() => new Map(members.map(m => [m.user_id, memberName(m)])), [members]);

  async function create() {
    if (!newName.trim()) { setError("Give the group a name."); return; }
    setBusy(true); setError(null);
    const res = await fetchOrError("/api/org/groups", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: newName.trim(), description: newDesc.trim() }),
    });
    setBusy(false);
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { setError(d?.error ?? "Could not create the group."); return; }
    setNewName(""); setNewDesc(""); setCreating(false);
    await load();
    onChanged?.();
    // Jump straight into choosing members for the new group.
    if (d?.id) { setOpenId(d.id); setEditName(newName.trim()); setEditMembers([]); setQ(""); }
  }

  function open(g: GroupRow) {
    if (openId === g.id) { setOpenId(null); return; }
    setOpenId(g.id); setEditName(g.name); setEditMembers(g.member_ids); setQ(""); setError(null);
  }

  async function saveGroup(g: GroupRow) {
    if (!editName.trim()) { setError("Give the group a name."); return; }
    setBusy(true); setError(null);
    const res = await fetchOrError("/api/org/groups", {
      method: "PATCH", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: g.id, name: editName.trim(), member_ids: editMembers }),
    });
    setBusy(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Could not save the group."); return; }
    setOpenId(null);
    await load();
    onChanged?.();
  }

  async function remove(g: GroupRow) {
    if (!confirm(`Delete the group “${g.name}”? Plans that target it will no longer reach its members.`)) return;
    const res = await fetchOrError(`/api/org/groups?id=${encodeURIComponent(g.id)}`, { method: "DELETE" });
    if (!res.ok) { setError("Could not delete the group."); return; }
    if (openId === g.id) setOpenId(null);
    await load();
    onChanged?.();
  }

  if (groups === null) return null;
  const shown = q.trim() ? roster.filter(m => memberName(m).toLowerCase().includes(q.trim().toLowerCase())) : roster;

  return (
    <Card>
      <div className="flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-sm font-bold text-white">
          <UsersRound className="h-4 w-4 text-cyber-300" /> Groups
        </h2>
        <Button variant="outline" size="sm" onClick={() => { setCreating(v => !v); setError(null); }}>
          {creating ? <X className="mr-1.5 h-4 w-4" /> : <Plus className="mr-1.5 h-4 w-4" />}
          {creating ? "Cancel" : "New group"}
        </Button>
      </div>
      <p className="mt-1 text-xs text-slate-400">Cohorts inside your organisation that a learning plan can target, e.g. “Tier-1 analysts”.</p>

      {error && <p className="mt-2 text-xs text-severity-high">{error}</p>}

      {creating && (
        <div className="mt-3 flex flex-wrap gap-2 rounded-lg border border-border bg-bg-elevated p-3">
          <input
            value={newName} onChange={e => setNewName(e.target.value)} maxLength={PLAN_LIMITS.groupName} placeholder="Group name (e.g. Tier-1 analysts)"
            className="min-w-[200px] flex-1 rounded-md border border-border bg-bg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none"
          />
          <input
            value={newDesc} onChange={e => setNewDesc(e.target.value)} maxLength={PLAN_LIMITS.groupDescription} placeholder="Description (optional)"
            className="min-w-[200px] flex-1 rounded-md border border-border bg-bg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none"
          />
          <Button variant="primary" size="sm" disabled={busy} onClick={create}>
            {busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Plus className="mr-1.5 h-4 w-4" />} Create
          </Button>
        </div>
      )}

      {groups.length === 0 ? (
        <p className="mt-3 text-sm text-slate-400">No groups yet.</p>
      ) : (
        <div className="mt-3 space-y-2">
          {groups.map(g => {
            const isOpen = openId === g.id;
            return (
              <div key={g.id} className="rounded-lg border border-border bg-bg-elevated">
                <div className="flex items-center gap-2 px-3 py-2">
                  <button onClick={() => open(g)} className="flex min-w-0 flex-1 items-center gap-2 text-left">
                    <ChevronRight className={`h-3.5 w-3.5 shrink-0 text-slate-500 transition-transform ${isOpen ? "rotate-90" : ""}`} />
                    <span className="truncate text-sm font-medium text-slate-100">{g.name}</span>
                    <span className="shrink-0 font-mono text-[10px] text-slate-500">{g.member_ids.length} member{g.member_ids.length === 1 ? "" : "s"}</span>
                    {!isOpen && g.member_ids.length > 0 && (
                      <span className="hidden min-w-0 truncate text-[11px] text-slate-500 sm:inline">
                        · {g.member_ids.slice(0, 4).map(id => nameOf.get(id) ?? "—").join(", ")}{g.member_ids.length > 4 ? "…" : ""}
                      </span>
                    )}
                  </button>
                  <button onClick={() => open(g)} aria-label={`Edit ${g.name}`} title="Edit"
                    className="rounded p-1 text-slate-500 transition hover:bg-white/5 hover:text-slate-200"><Pencil className="h-3.5 w-3.5" /></button>
                  <button onClick={() => remove(g)} aria-label={`Delete ${g.name}`} title="Delete"
                    className="rounded p-1 text-slate-500 transition hover:bg-severity-high/10 hover:text-severity-high"><Trash2 className="h-3.5 w-3.5" /></button>
                </div>
                {g.description && !isOpen && <p className="px-3 pb-2 pl-9 text-[11px] text-slate-500">{g.description}</p>}

                {isOpen && (
                  <div className="space-y-2 border-t border-border/60 px-3 py-3">
                    <input
                      value={editName} onChange={e => setEditName(e.target.value)} maxLength={PLAN_LIMITS.groupName} aria-label="Group name"
                      className="w-full rounded-md border border-border bg-bg px-3 py-1.5 text-sm text-slate-100 focus:border-cyber-500/50 focus:outline-none"
                    />
                    <div className="flex items-center gap-2 rounded-md border border-border bg-bg px-2.5 py-1.5">
                      <Search className="h-3.5 w-3.5 shrink-0 text-slate-500" />
                      <input value={q} onChange={e => setQ(e.target.value)} placeholder="Find a learner…"
                        className="flex-1 bg-transparent text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none" />
                      <span className="font-mono text-[10px] text-slate-500">{editMembers.length} selected</span>
                    </div>
                    <div className="grid max-h-48 grid-cols-1 gap-0.5 overflow-y-auto sm:grid-cols-2">
                      {shown.map(m => (
                        <label key={m.user_id} className="flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-[12px] text-slate-300 hover:bg-white/5">
                          <input
                            type="checkbox" className="accent-cyan-500"
                            checked={editMembers.includes(m.user_id)}
                            onChange={() => setEditMembers(list => (list.includes(m.user_id) ? list.filter(x => x !== m.user_id) : [...list, m.user_id]))}
                          />
                          <span className="min-w-0 flex-1 truncate">{memberName(m)}</span>
                          {m.handle && <span className="truncate font-mono text-[10px] text-slate-500">@{m.handle}</span>}
                        </label>
                      ))}
                      {shown.length === 0 && <p className="px-1.5 text-[11px] text-slate-500">No matching learners.</p>}
                    </div>
                    <div className="flex justify-end gap-2">
                      <Button variant="ghost" size="sm" onClick={() => setOpenId(null)}>Cancel</Button>
                      <Button variant="primary" size="sm" disabled={busy} onClick={() => saveGroup(g)}>
                        {busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Save className="mr-1.5 h-4 w-4" />} Save group
                      </Button>
                    </div>
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
