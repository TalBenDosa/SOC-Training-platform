"use client";
/**
 * The SOC queue at a glance, above the shared feed for every role: how many alerts wait with
 * nobody on them, who is investigating what, how many are past their triage SLA, escalated,
 * or closed. A projection of the room's own events (claims, dispositions, escalations): it
 * shows what the TEAM did, never the answer key.
 */
import { Inbox, Search, Timer, ArrowUpRight, CheckCircle2, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

export interface QueueStats {
  inQueue: number;
  oldestMins: number | null;
  investigating: number;
  byWho: { name: string; n: number }[];
  breached: number;
  orphans: number;
  escalatedOpen: number;
  escalatedTotal: number;
  closed: number;
  verdictNotEscalated: number;
  withMedium: boolean;
}

export function QueueBoard({ q }: { q: QueueStats }) {
  const tiles: { key: string; icon: typeof Inbox; label: string; value: number; sub: string; tone: string; tip: string }[] = [
    { key: "queue", icon: Inbox, label: "In queue", value: q.inQueue,
      sub: q.inQueue ? `oldest waiting ${q.oldestMins ?? 0} min` : "nothing waiting",
      tone: q.inQueue ? "text-white" : "text-slate-400",
      tip: `${q.withMedium ? "Medium, high and critical" : "High and critical"} alerts with no verdict that nobody has taken yet.` },
    { key: "inv", icon: Search, label: "Under investigation", value: q.investigating,
      sub: q.byWho.length ? q.byWho.map(w => `${w.name} ${w.n}`).join(" · ") : "nobody yet",
      tone: "text-cyber-300", tip: "Alerts an analyst took and is working now." },
    { key: "sla", icon: Timer, label: "Past SLA", value: q.breached,
      sub: q.orphans ? `${q.orphans} with nobody on them` : "triage SLA: 15 min (low 30)",
      tone: q.breached ? "text-severity-high" : "text-slate-400", tip: "Untriaged alerts older than their triage SLA: 15 minutes for an alert that may need escalation, 30 for low." },
    { key: "esc", icon: ArrowUpRight, label: "Escalated, open", value: q.escalatedOpen,
      sub: `${q.escalatedTotal} escalated in total`, tone: "text-neon-amber", tip: "Escalated to Tier-2 and not resolved yet." },
    { key: "closed", icon: CheckCircle2, label: "Closed", value: q.closed,
      sub: "false positive or benign", tone: "text-neon-green", tip: "Closed by Tier-1 as false positive or benign." },
  ];
  return (
    <div data-tour="queue-board" className="rounded-lg border border-border bg-bg-elevated/60 p-2">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        {tiles.map(t => {
          const Icon = t.icon;
          return (
            <div key={t.key} className="rounded-md border border-border/70 bg-bg px-2.5 py-1.5" title={t.tip}>
              <p className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-slate-400"><Icon className="h-3 w-3" aria-hidden />{t.label}</p>
              <p className={cn("font-mono text-lg font-bold leading-tight", t.tone)}>{t.value}</p>
              <p className="truncate text-[10px] text-slate-500" title={t.sub}>{t.sub}</p>
            </div>
          );
        })}
      </div>
      {q.verdictNotEscalated > 0 && (
        <p className="mt-1.5 flex items-center gap-1.5 px-1 text-[11px] text-neon-amber">
          <AlertTriangle className="h-3 w-3" aria-hidden />
          {q.verdictNotEscalated} alert{q.verdictNotEscalated === 1 ? " was" : "s were"} called an attack or suspicious but not escalated yet.
        </p>
      )}
    </div>
  );
}
