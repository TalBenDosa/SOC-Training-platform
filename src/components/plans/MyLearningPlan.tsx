"use client";
/**
 * "My learning plan" — the learner's view of what their organisation set them
 * (migration 0075): their personal plan first, then group / org-wide plans by
 * priority and due date. Items keep the manager's order within each priority,
 * show notes and instructions, tick ✓ when done and deep-link to the item.
 *
 * Renders nothing for solo learners (no org, no plans, or an error), so the
 * self-paced experience is untouched. `compact` (the SOC dashboard) shows the
 * next few open items with a toggle for the full plan; the full card is used on
 * /learn and /rooms.
 *
 * Status is derived server-side from the progress tables, so something finished
 * last week is already ✓ the moment it's assigned.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { ClipboardList, CalendarClock, ChevronDown, CheckCircle2, User } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { StatusIcon, KIND_LABEL } from "@/components/plans/PlanItemsEditor";
import { countDone, dedupeItems, isOverdue } from "@/lib/plans/completion";
import { formatDueDate, itemKey, type LearnerPlan, type ResolvedPlanItem } from "@/lib/plans/types";

function ItemRow({ it }: { it: ResolvedPlanItem }) {
  const done = it.status === "done";
  return (
    <Link
      href={it.href}
      className={`group flex items-start gap-2 rounded-md border px-2.5 py-1.5 transition ${
        done ? "border-neon-green/20 bg-neon-green/5" : "border-border bg-bg-elevated hover:border-cyber-500/50"
      }`}
    >
      <span className="mt-0.5"><StatusIcon status={it.status} /></span>
      <span className="min-w-0 flex-1">
        <span className={`block truncate text-[12px] ${done ? "text-slate-400 line-through decoration-slate-600" : "text-slate-100 group-hover:text-white"}`}>{it.title}</span>
        {it.note && <span className="mt-0.5 block text-[11px] italic text-slate-400">{it.note}</span>}
      </span>
      {it.priority === 1 && !done && <span className="shrink-0 text-[9px] font-bold uppercase tracking-wider text-neon-amber">High</span>}
      <span className="shrink-0 text-[9px] uppercase tracking-wider text-slate-500">{KIND_LABEL[it.kind]}</span>
    </Link>
  );
}

/**
 * One plan as a collapsible card. Collapsed by default — a long plan (20+ rooms)
 * used to fill the whole screen — showing just what a learner scans for: title,
 * who set it, priority, due date, a progress bar and the next open task. Tapping
 * the card reveals the manager's instructions and the full task list.
 */
function PlanBlock({ p }: { p: LearnerPlan }) {
  const [open, setOpen] = useState(false);
  const statuses = p.items.map(i => i.status ?? "not_started");
  const { done, tracked } = countDone(statuses);
  const complete = tracked > 0 && done === tracked;
  const overdue = isOverdue(p.due_at, statuses);
  const pct = tracked > 0 ? Math.round((done / tracked) * 100) : 0;
  const next = p.items.find(i => i.status !== "done" && i.status !== "untracked");
  const panelId = `plan-${p.id}`;
  return (
    <div className={`rounded-lg border bg-bg transition ${open ? "border-neon-purple/40" : "border-border hover:border-neon-purple/30"}`}>
      <button type="button" onClick={() => setOpen(v => !v)} aria-expanded={open} aria-controls={panelId}
        className="w-full rounded-lg p-3 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neon-purple/50">
        <div className="flex items-start gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <p className="truncate text-sm font-semibold text-white">{p.title}</p>
              {p.personal ? (
                <span className="inline-flex items-center gap-1 rounded border border-neon-purple/40 bg-neon-purple/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-neon-purple">
                  <User className="h-2.5 w-2.5" /> Personal
                </span>
              ) : (
                <span className="text-[10px] text-slate-500">for {p.via.join(", ")}</span>
              )}
              {p.priority === 1 && <span className="rounded border border-neon-amber/40 bg-neon-amber/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-neon-amber">High priority</span>}
            </div>
            <div className="mt-2 flex items-center gap-2">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/5" aria-hidden>
                <div className={`h-full rounded-full ${complete ? "bg-neon-green" : "bg-cyber-500"}`} style={{ width: `${pct}%` }} />
              </div>
              <span className={`shrink-0 font-mono text-[11px] font-bold ${complete ? "text-neon-green" : "text-cyber-300"}`}>{done}/{tracked}</span>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
              {p.due_at && (
                <span className={overdue ? "font-semibold text-severity-high" : "text-slate-400"}>
                  <CalendarClock className="mr-1 inline h-3 w-3" />
                  {overdue ? "Overdue — " : "Due "}{formatDueDate(p.due_at)}
                </span>
              )}
              {!open && (complete
                ? <span className="inline-flex items-center gap-1 text-neon-green"><CheckCircle2 className="h-3 w-3" /> All done</span>
                : next && <span className="min-w-0 truncate text-slate-400">Next: <span className="text-slate-200">{next.title}</span></span>)}
            </div>
          </div>
          <span className="mt-0.5 inline-flex shrink-0 items-center gap-1 text-[11px] text-slate-400">
            <span className="hidden sm:inline">{open ? "Hide tasks" : `${p.items.length} tasks`}</span>
            <ChevronDown className={`h-4 w-4 transition-transform motion-reduce:transition-none ${open ? "rotate-180" : ""}`} />
          </span>
        </div>
      </button>
      {open && (
        <div id={panelId} className="border-t border-border/60 px-3 pb-3 pt-2">
          {p.instructions && <p className="mb-2 whitespace-pre-line text-[11px] text-slate-400">{p.instructions}</p>}
          <div className="grid gap-1.5 sm:grid-cols-2">
            {p.items.map(it => <ItemRow key={itemKey(it)} it={it} />)}
          </div>
        </div>
      )}
    </div>
  );
}

export function MyLearningPlan({ compact = false }: { compact?: boolean }) {
  const [plans, setPlans] = useState<LearnerPlan[]>([]);
  const [expanded, setExpanded] = useState(!compact);
  // E-23 (QA phase 7): a server/network failure hid an enrolled student's
  // assigned plan with no hint. 4xx (solo learner, no org) still renders nothing.
  const [failed, setFailed] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let alive = true;
    setFailed(false);
    fetch("/api/org/assignments?view=mine")
      .then(r => {
        if (r.status >= 500) throw new Error(`status ${r.status}`);
        return r.ok ? r.json() : { plans: [] };
      })
      .then(d => { if (alive) setPlans(Array.isArray(d?.plans) ? d.plans : []); })
      .catch(() => { if (alive) setFailed(true); });
    return () => { alive = false; };
  }, [attempt]);

  if (failed && plans.length === 0) {
    return (
      <Card className="border-neon-purple/30 bg-neon-purple/5">
        <p role="status" className="text-sm text-slate-300">
          Couldn&apos;t load your learning plan just now.{" "}
          <button onClick={() => setAttempt(a => a + 1)} className="font-semibold text-neon-purple hover:underline">Try again</button>
        </p>
      </Card>
    );
  }
  if (plans.length === 0) return null;

  // Deduped: the same room can sit in two plans but is one piece of work.
  const unique = dedupeItems(plans.flatMap(p => p.items));
  const { done, tracked } = countDone(unique.map(i => i.status ?? "not_started"));
  // Next open items in plan order (personal first, then priority).
  const upNext = unique.filter(i => i.status !== "done" && i.status !== "untracked").slice(0, 3);

  return (
    <Card className="border-neon-purple/30 bg-neon-purple/5">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h3 className="flex items-center gap-2 text-sm font-bold text-white">
          <ClipboardList className="h-4 w-4 text-neon-purple" /> My learning plan
        </h3>
        <div className="flex items-center gap-3">
          <span className={`font-mono text-[11px] font-bold ${tracked > 0 && done === tracked ? "text-neon-green" : "text-cyber-300"}`}>{done}/{tracked} done</span>
          {compact && (
            <button onClick={() => setExpanded(v => !v)} aria-expanded={expanded} className="inline-flex items-center gap-1 text-[11px] text-slate-400 transition hover:text-white">
              {expanded ? "Hide plan" : "Full plan"} <ChevronDown aria-hidden="true" className={`h-3.5 w-3.5 transition-transform ${expanded ? "rotate-180" : ""}`} />
            </button>
          )}
        </div>
      </div>

      {compact && !expanded && (
        upNext.length === 0 ? (
          <p className="flex items-center gap-1.5 text-xs text-neon-green"><CheckCircle2 className="h-4 w-4" /> All caught up — everything assigned to you is done.</p>
        ) : (
          <div>
            <p className="mb-1.5 text-[10px] uppercase tracking-wider text-slate-500">Up next</p>
            <div className="grid gap-1.5 sm:grid-cols-3">
              {upNext.map(it => <ItemRow key={itemKey(it)} it={it} />)}
            </div>
          </div>
        )
      )}

      {expanded && (
        <div className="space-y-3">
          {plans.map(p => <PlanBlock key={p.id} p={p} />)}
        </div>
      )}
    </Card>
  );
}
