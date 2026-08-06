"use client";
/**
 * "Set by your instructor" — the student's view of coursework (migration 0021).
 *
 * Renders nothing at all for solo learners: no org, no assignments, or an error
 * all collapse to null, so the self-paced experience is untouched and only
 * enrolled cohorts see a homework panel.
 *
 * Progress comes from the API, which derives it from room_progress /
 * scenario_history — so an item the student already finished shows as done the
 * moment it's assigned.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { ClipboardList, CalendarClock, Check } from "lucide-react";
import { Card } from "@/components/ui/Card";
import type { AssignmentRow } from "@/app/api/org/assignments/route";

export function AssignedWork() {
  const [assignments, setAssignments] = useState<AssignmentRow[]>([]);

  useEffect(() => {
    let alive = true;
    fetch("/api/org/assignments")
      .then(r => (r.ok ? r.json() : { assignments: [] }))
      .then(d => { if (alive) setAssignments(d.assignments ?? []); })
      .catch(() => {});
    return () => { alive = false; };
  }, []);

  if (assignments.length === 0) return null;

  return (
    <Card className="border-neon-purple/30 bg-neon-purple/5">
      <h3 className="mb-3 flex items-center gap-2 text-sm font-bold text-white">
        <ClipboardList className="h-4 w-4 text-neon-purple" /> Set by your instructor
      </h3>
      <div className="space-y-3">
        {assignments.map(a => {
          const done = new Set(a.my_done_ids ?? []);
          const total = a.item_titles.length;
          const doneCount = a.item_titles.filter(t => done.has(`${t.kind}:${t.id}`)).length;
          const complete = total > 0 && doneCount === total;
          const overdue = !complete && a.due_at && Date.parse(a.due_at) < Date.now();

          return (
            <div key={a.id} className="rounded-lg border border-border bg-bg p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-sm font-semibold text-white">{a.title}</p>
                <div className="flex items-center gap-2">
                  {a.due_at && (
                    <span className={`text-[11px] ${overdue ? "text-severity-high" : "text-slate-400"}`}>
                      <CalendarClock className="mr-1 inline h-3 w-3" />
                      {overdue ? "Overdue — " : "Due "}{new Date(a.due_at).toLocaleDateString("en-GB")}
                    </span>
                  )}
                  <span className={`font-mono text-[11px] font-bold ${complete ? "text-neon-green" : "text-cyber-300"}`}>
                    {doneCount}/{total}
                  </span>
                </div>
              </div>

              {a.instructions && <p className="mt-1 text-[11px] text-slate-400">{a.instructions}</p>}

              <div className="mt-2 flex flex-wrap gap-1.5">
                {a.item_titles.map(t => {
                  const isDone = done.has(`${t.kind}:${t.id}`);
                  const href = t.kind === "room" ? `/rooms/${t.id}` : `/scenarios/${t.id}`;
                  return (
                    <Link
                      key={`${t.kind}:${t.id}`} href={href}
                      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] transition ${
                        isDone
                          ? "border-neon-green/30 bg-neon-green/10 text-neon-green"
                          : "border-border bg-bg-elevated text-slate-300 hover:border-cyber-500/50 hover:text-white"
                      }`}
                    >
                      {isDone && <Check className="h-3 w-3" />}
                      {t.title}
                    </Link>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
