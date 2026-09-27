"use client";
/**
 * Per-plan progress: one row per recipient, one column per item — done ✓ / in
 * progress ◐ / not started · (untracked items show —). The row total counts
 * tracked items only, and a learner past the due date who hasn't finished is
 * flagged overdue. Data comes pre-computed from GET /api/org/assignments
 * (statuses are one character per item; see STATUS_CODE).
 */
import Link from "next/link";
import { AlertTriangle } from "lucide-react";
import { countDone, isOverdue } from "@/lib/plans/completion";
import { CODE_STATUS, type ItemStatus, type StaffPlan } from "@/lib/plans/types";

const CELL: Record<ItemStatus, { glyph: string; cls: string; label: string }> = {
  done:        { glyph: "✓", cls: "bg-neon-green/15 text-neon-green", label: "done" },
  in_progress: { glyph: "◐", cls: "bg-neon-amber/10 text-neon-amber", label: "in progress" },
  not_started: { glyph: "·", cls: "text-slate-600",                   label: "not started" },
  untracked:   { glyph: "—", cls: "text-slate-700",                   label: "not tracked" },
};

export function PlanProgressMatrix({ plan }: { plan: StaffPlan }) {
  if (plan.progress.length === 0) {
    return <p className="text-xs text-slate-500">No active learners receive this plan yet.</p>;
  }
  const now = Date.now();
  return (
    <div className="space-y-2">
      <ol className="grid grid-cols-1 gap-x-4 gap-y-0.5 text-[11px] text-slate-400 sm:grid-cols-2">
        {plan.items.map((it, i) => (
          <li key={`${it.kind}:${it.id}`} className="flex min-w-0 gap-1.5">
            <span className="w-5 shrink-0 text-right font-mono text-slate-500">{i + 1}</span>
            <span className="truncate" title={it.title}>{it.title}</span>
          </li>
        ))}
      </ol>
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-left text-[12px]">
          <thead>
            <tr className="border-b border-border text-[10px] uppercase tracking-wider text-slate-400">
              <th className="sticky left-0 bg-bg-elevated px-3 py-2 font-medium">Learner</th>
              {plan.items.map((it, i) => (
                <th key={`${it.kind}:${it.id}`} className="px-1 py-2 text-center font-mono font-medium" title={it.title}>{i + 1}</th>
              ))}
              <th className="px-3 py-2 text-right font-medium">Done</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/60">
            {plan.progress.map(row => {
              const st = [...row.statuses].map(c => CODE_STATUS[c] ?? "not_started");
              const { done, tracked } = countDone(st);
              const overdue = isOverdue(plan.due_at, st, now);
              return (
                <tr key={row.user_id} className="hover:bg-white/[0.02]">
                  <td className="sticky left-0 bg-bg-elevated px-3 py-1.5">
                    <Link href={`/manage/students/${row.user_id}`} className="text-slate-200 hover:text-cyber-300">{row.name}</Link>
                    {overdue && (
                      <span className="ml-2 inline-flex items-center gap-0.5 text-[10px] font-semibold text-severity-high">
                        <AlertTriangle className="h-3 w-3" /> overdue
                      </span>
                    )}
                  </td>
                  {st.map((s, i) => (
                    <td key={i} className="px-1 py-1.5 text-center">
                      <span title={`${plan.items[i]?.title ?? ""} — ${CELL[s].label}`}
                        className={`inline-flex h-5 w-5 items-center justify-center rounded font-mono text-[11px] ${CELL[s].cls}`}>
                        {CELL[s].glyph}
                      </span>
                    </td>
                  ))}
                  <td className={`px-3 py-1.5 text-right font-mono text-[11px] ${tracked > 0 && done === tracked ? "font-bold text-neon-green" : "text-slate-400"}`}>
                    {done}/{tracked}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="text-[10px] text-slate-500">✓ done · ◐ in progress · · not started · — not tracked (custom library lessons record no completion)</p>
    </div>
  );
}
