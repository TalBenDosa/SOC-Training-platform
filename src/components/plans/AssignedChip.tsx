"use client";
/**
 * The small "Assigned" chip shown on room cards, Learning Path lesson rows,
 * library lesson cards, quiz cards and scenario cards for anything that sits in
 * a plan the current learner receives (migration 0075). Shows the highest
 * priority across their plans and whether it's done; the due date is in the
 * tooltip. Renders nothing when the item isn't assigned — so solo learners and
 * users without an org never see it.
 *
 * Same visual language as "My learning plan": purple = assigned, amber = high
 * priority, green = done.
 */
import { CheckCircle2, ClipboardList } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDueDate } from "@/lib/plans/types";
import type { AssignedInfo } from "@/lib/plans/assigned";
import { useAssignedItems } from "@/lib/plans/useAssigned";

function tooltip(info: AssignedInfo): string {
  const who = info.personal ? "In your personal priorities" : "Assigned to you by your organisation";
  if (info.done) return `${who} — done`;
  if (!info.due_at) return who;
  const overdue = Date.parse(info.due_at) < Date.now();
  return `${who} — ${overdue ? "overdue since" : "due"} ${formatDueDate(info.due_at)}`;
}

export function AssignedChip({ info, className }: { info?: AssignedInfo | null; className?: string }) {
  if (!info) return null;
  const label = info.done ? "Done" : info.priority === 1 ? "High" : info.priority === 3 ? "Low" : null;
  const tone = info.done
    ? "border-neon-green/40 bg-neon-green/10 text-neon-green"
    : info.priority === 1
      ? "border-neon-amber/40 bg-neon-amber/10 text-neon-amber"
      : "border-neon-purple/40 bg-neon-purple/10 text-neon-purple";
  const Icon = info.done ? CheckCircle2 : ClipboardList;
  return (
    <span
      title={tooltip(info)}
      className={cn(
        "inline-flex shrink-0 items-center gap-1 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider",
        tone,
        className,
      )}
    >
      <Icon className="h-2.5 w-2.5" />
      Assigned{label ? ` · ${label}` : ""}
    </span>
  );
}

/** Self-fetching chip for lists rendered on the server (e.g. a Learning Path page). */
export function AssignedItemChip({ itemKey, className }: { itemKey: string; className?: string }) {
  const items = useAssignedItems();
  return <AssignedChip info={items[itemKey]} className={className} />;
}

/**
 * "N assigned to you · M done" for a group of items (a Learning Path). Renders
 * nothing when none of them is assigned.
 */
export function AssignedCount({ itemKeys, noun = "lesson", className }: { itemKeys: readonly string[]; noun?: string; className?: string }) {
  const items = useAssignedItems();
  const hits = itemKeys.map(k => items[k]).filter((x): x is AssignedInfo => !!x);
  if (hits.length === 0) return null;
  const done = hits.filter(h => h.done).length;
  const high = hits.some(h => h.priority === 1 && !h.done);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider",
        done === hits.length
          ? "border-neon-green/40 bg-neon-green/10 text-neon-green"
          : high
            ? "border-neon-amber/40 bg-neon-amber/10 text-neon-amber"
            : "border-neon-purple/40 bg-neon-purple/10 text-neon-purple",
        className,
      )}
    >
      <ClipboardList className="h-3 w-3" />
      {hits.length} {noun}{hits.length === 1 ? "" : "s"} assigned to you · {done} done
    </span>
  );
}
