"use client";
import { Eye } from "lucide-react";

/**
 * Tier-2's queue as a Tier-3 sees it (T3 interface spec, stage A). When the team has a Tier-2,
 * the Tier-3 does not work that queue: it is folded and read-only (a disabled fieldset turns off
 * every control inside it), so the Tier-3's own work stays in the Case tab and the inbox. With no
 * Tier-2 in the team, the queue is the Tier-3's to work, exactly as before.
 */
export function T3QueueGate({ readOnly, children }: { readOnly: boolean; children: React.ReactNode }) {
  if (!readOnly) return <>{children}</>;
  return (
    <details className="group rounded-lg border border-border bg-bg-elevated/40">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs font-semibold text-slate-300 hover:text-white">
        <Eye className="h-3.5 w-3.5 text-slate-400" aria-hidden /> Tier-2&apos;s queue (read-only)
        <span className="ml-auto text-[11px] font-normal text-slate-400">Tier-2 works it. A case reaches you as a hand-off in your inbox.</span>
      </summary>
      <fieldset disabled aria-label="Tier-2 queue, read-only" className="min-w-0 border-0 p-2 pt-0">{children}</fieldset>
    </details>
  );
}
