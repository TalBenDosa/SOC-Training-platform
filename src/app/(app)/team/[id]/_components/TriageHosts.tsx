"use client";
/**
 * Tier-1 "Needs triage" by host (Sdema review 2026-10-25): one line per host with what is waiting
 * on it and whether it is already in hand. A host nobody has touched is flagged NEW and sits on
 * top; a host with an open case or an isolation says who has it and offers "Add to case", so its
 * alerts go into that case as evidence instead of three more escalations for one incident.
 */
import { useState } from "react";
import { Monitor, ShieldCheck, FolderOpen, Sparkles, FolderPlus } from "lucide-react";
import { cn } from "@/lib/utils";
import type { HostGroup } from "@/lib/team/hostCases";

const SEV_CLS: Record<string, string> = {
  critical: "border-severity-critical/50 bg-severity-critical/15 text-severity-critical",
  high: "border-severity-high/50 bg-severity-high/10 text-severity-high",
  medium: "border-neon-amber/40 bg-neon-amber/10 text-neon-amber",
};

export function TriageHosts({ groups, nameOf, meId, claims, activeHost, onShowHost, onAddToCase, onTakeHost }: {
  groups: HostGroup[];
  nameOf: (u: string | null) => string;
  meId: string;
  claims: Map<string, { by: string }>;
  activeHost: string;
  onShowHost: (host: string) => void;
  onAddToCase: (eids: string[]) => Promise<string | null>;
  onTakeHost: (g: HostGroup) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<{ key: string; text: string; ok: boolean } | null>(null);
  const who = (u: string | null) => (u === meId ? "you" : nameOf(u));
  return (
    <div data-tour="triage-hosts" className="rounded-lg border border-border bg-bg-elevated/40 p-2">
      <p className="mb-1.5 flex items-center gap-1.5 px-1 text-[10px] uppercase tracking-wider text-slate-400">
        <Monitor className="h-3 w-3" aria-hidden /> By host · new hosts first, hosts already in a case last
      </p>
      <ul className="space-y-1">
        {groups.map(g => {
          // Only alerts nobody else is working can be added for them.
          const free = g.items.filter(q => { const c = claims.get(q.eid); return !c || c.by === meId; });
          const shown = activeHost !== "all" && activeHost.toLowerCase() === g.key;
          return (
            <li key={g.key || "_none"} className={cn("flex flex-wrap items-center gap-x-2 gap-y-1 rounded-md border px-2 py-1.5 text-[11px]",
              g.fresh ? "border-severity-high/50 bg-severity-high/[0.06]" : g.covered ? "border-border/60 bg-bg/60" : "border-border bg-bg")}>
              <button type="button" disabled={!g.key} onClick={() => onShowHost(g.host)} title={g.key ? (shown ? "Show every host again" : `Show only ${g.host} in the table`) : undefined}
                className={cn("font-mono font-semibold", shown ? "text-cyber-200 underline" : "text-slate-100 hover:underline", !g.key && "cursor-default text-slate-400 hover:no-underline")}>
                <bdi>{g.host}</bdi>
              </button>
              <span className="text-slate-400">{g.items.length} waiting</span>
              {g.maxSeverity && <span className={cn("rounded border px-1 text-[9px] font-bold uppercase", SEV_CLS[g.maxSeverity] ?? "border-border text-slate-400")}>{g.maxSeverity}</span>}
              <span className={cn("font-mono text-[10px]", g.orphans ? "text-severity-high" : "text-slate-500")}>oldest {g.oldestMins}m{g.orphans ? ` · ${g.orphans} past SLA, nobody on them` : ""}</span>
              {g.fresh && <span className="flex items-center gap-1 rounded border border-severity-high/50 px-1 text-[9px] font-bold uppercase text-severity-high" title="Nobody has escalated, judged or isolated anything on this host yet: this may be a new incident"><Sparkles className="h-3 w-3" aria-hidden />New host</span>}
              {g.isolated && <span className="flex items-center gap-1 rounded border border-neon-green/40 bg-neon-green/10 px-1 text-[9px] font-semibold text-neon-green"><ShieldCheck className="h-3 w-3" aria-hidden />Isolated · <bdi>{who(g.isolated.by)}</bdi>{g.isolated.at ? ` ${g.isolated.at.slice(11, 16)}` : ""}</span>}
              {g.case && (
                <span className="flex min-w-0 items-center gap-1 rounded border border-cyber-500/40 bg-cyber-500/10 px-1 text-[9px] font-semibold text-cyber-200" title={g.case.label}>
                  <FolderOpen className="h-3 w-3 shrink-0" aria-hidden />{g.case.owner ? <>Case open · <bdi>{who(g.case.owner)}</bdi></> : "Escalated, waiting for Tier-2"}
                </span>
              )}
              <span className="ml-auto flex items-center gap-1.5">
                {g.case && free.length > 0 && (
                  <button type="button" disabled={busy === g.key}
                    onClick={async () => { setBusy(g.key); const err = await onAddToCase(free.map(q => q.eid)); setBusy(null); setNote({ key: g.key, ok: !err, text: err ?? `Added to ${g.case!.owner ? `${who(g.case!.owner)}'s` : "the"} case.` }); }}
                    title="Add these alerts to the open case on this host as evidence. No new escalation and no verdict per log: the case owner sees them in the case."
                    className="flex items-center gap-1 rounded border border-cyber-500/50 bg-cyber-500/10 px-2 py-0.5 font-semibold text-cyber-200 transition hover:bg-cyber-500/20 disabled:opacity-50">
                    <FolderPlus className="h-3 w-3" aria-hidden />Add {free.length === 1 ? "it" : `all ${free.length}`} to case
                  </button>
                )}
                {free.length > 0 && (
                  <button type="button" onClick={() => onTakeHost(g)} className="rounded border border-border px-2 py-0.5 text-slate-300 transition hover:border-cyber-500/40 hover:text-cyber-200">
                    Take next here
                  </button>
                )}
              </span>
              {note?.key === g.key && <span role="status" className={cn("basis-full text-[10px]", note.ok ? "text-neon-green" : "text-neon-amber")}>{note.text}</span>}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
