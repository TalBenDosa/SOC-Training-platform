"use client";
/**
 * Personal priorities for ONE learner (student page) — "David gets lessons X, Y
 * and practice Z". The same module tree as the Learning plans panel with tick
 * V checkboxes; saving writes that learner's single personal plan
 * (PUT /api/org/students/[id]/plan — empty = remove). Each item shows the
 * learner's status (not started / in progress / done), and every other plan
 * that reaches them (org-wide, direct, via a group) is listed read-only below,
 * so the manager sees their whole workload in one place.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ListChecks, Loader2, Save, Clock, CalendarClock } from "lucide-react";
import { ModuleTree, indexLeaves } from "@/components/plans/ModuleTree";
import { PlanItemsEditor, StatusIcon } from "@/components/plans/PlanItemsEditor";
import { applyToggle, capNotice } from "@/lib/plans/selection";
import { PriorityChip } from "@/components/manage/LearningPlansPanel";
import { countDone } from "@/lib/plans/completion";
import { describeNotifyOutcome } from "@/lib/notifications/types";
import { PLAN_LIMITS, formatDueDate, itemKey, type CatalogNode, type ItemStatus, type PlanItem } from "@/lib/plans/types";
import type { PersonalPlanResponse } from "@/app/api/org/students/[id]/plan/route";

export function PersonalPrioritiesCard({ studentId, studentName }: { studentId: string; studentName: string }) {
  const [tree, setTree] = useState<CatalogNode[] | null>(null);
  const [treeError, setTreeError] = useState(false);
  const [capMsg, setCapMsg] = useState<string | null>(null);
  const [data, setData] = useState<PersonalPlanResponse | null>(null);
  const [items, setItems] = useState<PlanItem[]>([]);
  const [instructions, setInstructions] = useState("");
  const [due, setDue] = useState("");
  const [dirty, setDirty] = useState(false);
  // "Also email" — per save, starts OFF; the in-app notification is always sent.
  const [notifyEmail, setNotifyEmail] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null); setTreeError(false);
    const [cRes, pRes] = await Promise.all([
      fetch("/api/org/catalog").catch(() => null),
      fetch(`/api/org/students/${studentId}/plan`).catch(() => null),
    ]);
    if (cRes?.ok) setTree((await cRes.json()).tree ?? []);
    else setTreeError(true);
    if (!pRes?.ok) { setError((await pRes?.json().catch(() => ({})))?.error ?? "Could not load the learner's plan."); return; }
    const d: PersonalPlanResponse = await pRes.json();
    setData(d);
    setItems((d.personal?.items ?? []).map(({ kind, id, priority, note }) => ({ kind, id, ...(priority ? { priority } : {}), ...(note ? { note } : {}) })));
    setInstructions(d.personal?.instructions ?? "");
    setDue(d.personal?.due_at ? d.personal.due_at.slice(0, 10) : "");
    setDirty(false);
  }, [studentId]);
  useEffect(() => { load(); }, [load]);

  const leaves = useMemo(() => indexLeaves(tree ?? []), [tree]);
  const selected = useMemo(() => new Set(items.map(itemKey)), [items]);

  // The learner's status on anything we already know about (personal + other plans).
  const statuses = useMemo(() => {
    const m: Record<string, ItemStatus> = {};
    for (const it of data?.personal?.items ?? []) if (it.status) m[itemKey(it)] = it.status;
    for (const p of data?.assigned ?? []) for (const it of p.items) if (it.status) m[itemKey(it)] = it.status;
    return m;
  }, [data]);

  function change(next: PlanItem[]) { setItems(next); setDirty(true); setNotice(null); setCapMsg(null); }
  function toggleKeys(keys: string[], sel: boolean) {
    const r = applyToggle(items, keys, sel, leaves);
    change(r.items);
    setCapMsg(capNotice(r.dropped));
  }

  async function save() {
    setBusy(true); setError(null);
    const res = await fetch(`/api/org/students/${studentId}/plan`, {
      method: "PUT", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ items, instructions: instructions.trim(), due_at: due || null, notify_email: notifyEmail }),
    });
    setBusy(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Could not save."); return; }
    // The real outcome from the API (notified / emailed / why an email was skipped).
    const outcome = describeNotifyOutcome(await res.json().catch(() => null));
    setNotice(items.length ? `Saved — ${studentName} sees these first in “My learning plan”.${outcome ? ` ${outcome}.` : ""}` : "Personal priorities cleared.");
    setNotifyEmail(false);
    await load();
  }

  const done = countDone(items.map(i => statuses[itemKey(i)] ?? "not_started"));

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-sm font-bold text-white">
          <ListChecks className="h-4 w-4 text-cyber-300" /> Personal priorities
        </h2>
        {items.length > 0 && <span className="font-mono text-[11px] text-slate-400">{done.done}/{done.tracked} done</span>}
      </div>
      <p className="mt-1 text-xs text-slate-400">
        Tick the modules and practice {studentName} should do first. They appear at the top of their learning plan, in this order.
      </p>
      {error && <p className="mt-2 text-xs text-severity-high">{error}</p>}
      {notice && !error && <p className="mt-2 text-xs text-neon-green">{notice}</p>}

      {(treeError || (error && !data)) ? (
        <div className="mt-3 flex items-center gap-3 rounded-lg border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-xs text-severity-high">
          {treeError ? "Could not load the module catalogue." : "Could not load this learner's plan."}
          <Button variant="outline" size="sm" onClick={load}>Retry</Button>
        </div>
      ) : !data || !tree ? (
        <div className="mt-3 flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
      ) : (
        <>
          <div className="mt-3 grid gap-3 md:grid-cols-2">
            <ModuleTree tree={tree} selected={selected} onToggle={toggleKeys} className="h-[380px]" />
            <div className="flex min-w-0 flex-col gap-2">
              {capMsg && <p className="rounded border border-neon-amber/40 bg-neon-amber/10 px-2 py-1 text-[11px] text-neon-amber">{capMsg}</p>}
              <PlanItemsEditor items={items} leaves={leaves} onChange={change} statuses={statuses} className="h-[270px]" />
              <textarea
                value={instructions} onChange={e => { setInstructions(e.target.value); setDirty(true); }} maxLength={PLAN_LIMITS.instructions} rows={2}
                placeholder={`A note for ${studentName} (optional)`}
                className="resize-none rounded-md border border-border bg-bg px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none"
              />
              <div className="flex flex-wrap items-center gap-2">
                <label className="flex flex-1 items-center gap-2 rounded-md border border-border bg-bg px-2.5 py-1.5 text-xs text-slate-400">
                  <Clock className="h-3.5 w-3.5 shrink-0" /> due
                  <input type="date" value={due} onChange={e => { setDue(e.target.value); setDirty(true); }} className="min-w-0 flex-1 bg-transparent text-slate-100 focus:outline-none" />
                </label>
                {items.length > 0 && (
                  <label
                    className="flex cursor-pointer items-center gap-1.5 whitespace-nowrap text-[11px] text-slate-300"
                    title={`${studentName} always gets an in-app notification when the list changes. Tick to also send one short email.`}
                  >
                    <input type="checkbox" checked={notifyEmail} onChange={e => setNotifyEmail(e.target.checked)} className="accent-cyan-500" />
                    Also email {studentName.split(" ")[0] || "learner"}
                  </label>
                )}
                <Button variant="primary" size="sm" disabled={busy || !dirty} onClick={save}>
                  {busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Save className="mr-1.5 h-4 w-4" />}
                  {items.length === 0 && data.personal ? "Clear plan" : "Save"}
                </Button>
              </div>
            </div>
          </div>

          {data.assigned.length > 0 && (
            <div className="mt-4 border-t border-border/60 pt-3">
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Also assigned to {studentName}</p>
              <div className="space-y-2">
                {data.assigned.map(p => {
                  const c = countDone(p.items.map(i => i.status ?? "not_started"));
                  return (
                    <div key={p.id} className="rounded-lg border border-border bg-bg-elevated px-3 py-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-medium text-slate-100">{p.title}</span>
                        <PriorityChip p={p.priority} />
                        <span className="text-[11px] text-slate-500">via {p.via.join(", ")}</span>
                        {p.due_at && (
                          <span className="text-[11px] text-slate-400"><CalendarClock className="mr-1 inline h-3 w-3" />{formatDueDate(p.due_at)}</span>
                        )}
                        <span className="ml-auto font-mono text-[11px] text-slate-400">{c.done}/{c.tracked}</span>
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
                        {p.items.map(it => (
                          <Link key={itemKey(it)} href={it.href} className="inline-flex items-center gap-1 rounded border border-border bg-bg px-1.5 py-0.5 text-[10px] text-slate-300 hover:border-cyber-500/40">
                            <StatusIcon status={it.status} /> {it.title}
                          </Link>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </>
      )}
    </Card>
  );
}
