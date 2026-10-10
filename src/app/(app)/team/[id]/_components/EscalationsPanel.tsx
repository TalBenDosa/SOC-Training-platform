"use client";
import { useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Siren, ShieldAlert, ArrowUpRight, FilePlus2 } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { escalationStates, containmentRequests } from "@/lib/team/projections";
import { useServerNow } from "@/lib/team/clock";

/**
 * Every escalation in the shift, for the SOC Manager: Tier-1 → Tier-2 escalations, Tier-2 →
 * Tier-3 elevations and containment requests, with who raised it, who owns it, where it stands,
 * Tier-1's own investigation, the Tier-2 report, and teammates' views on a containment. This is
 * what the manager translates for the business ("Add to report" prefills the stakeholder report).
 */

const ROLE: Record<string, string> = { t1: "Tier-1", t2: "Tier-2", t3: "Tier-3", mgr: "SOC Manager", lead: "Lead" };
const fmtAgo = (ms: number) => { const m = Math.max(0, Math.floor(ms / 60000)); return m < 1 ? "just now" : `${m} min ago`; };

export interface EscalationItem {
  key: string; kind: "escalation" | "elevation" | "containment"; seq: number; at: string | null;
  by: string | null; byRole: string | null; host: string; summary: string; status: string; owner: string | null;
}

export function EscalationsPanel({ events, nameOf, onAddToReport }: { events: Ev[]; nameOf: (u: string | null) => string; onAddToReport: (host: string, line: string) => void }) {
  const now = useServerNow(15_000);
  const [open, setOpen] = useState<string | null>(null);
  const feedById = useMemo(() => new Map(events.filter(e => e.type === "feed.event").map(e => [asStr((e.payload as { id?: unknown }).id), e.payload as Record<string, unknown>])), [events]);
  const states = useMemo(() => escalationStates(events), [events]);
  const conts = useMemo(() => containmentRequests(events), [events]);
  const reports = useMemo(() => events.filter(e => e.type === "report.submitted"), [events]);
  const advice = useMemo(() => events.filter(e => e.type === "containment.advised"), [events]);

  const items: (EscalationItem & { ev: Ev })[] = [];
  for (const st of states.values()) {
    if (!st.rounds) continue;
    const p = st.request.payload as { summary?: string; what?: string; hostname?: string; snapshot?: { hostname?: unknown } };
    const host = asStr(p.hostname) || asStr(p.snapshot?.hostname) || asStr((feedById.get(st.eid) ?? {}).hostname);
    items.push({ ev: st.request, key: `e:${st.eid}`, kind: "escalation", seq: st.request.seq, at: st.request.occurred_at ?? null, by: st.request.actor_id, byRole: st.request.role, host,
      summary: asStr(p.summary) || asStr(p.what) || "Escalated alert", status: st.resolved ? "resolved" : st.bounced ? "bounced" : st.acked ? "in progress" : "waiting", owner: st.owner });
  }
  for (const e of events.filter(x => x.type === "elevation.requested")) {
    const p = e.payload as { event_id?: string; reason?: string; question?: string; summary?: string };
    const eid = asStr(p.event_id);
    const acked = events.some(x => x.type === "elevation.acknowledged" && x.seq > e.seq && asStr((x.payload as { event_id?: unknown }).event_id) === eid);
    items.push({ ev: e, key: `v:${e.seq}`, kind: "elevation", seq: e.seq, at: e.occurred_at ?? null, by: e.actor_id, byRole: e.role, host: asStr((feedById.get(eid) ?? {}).hostname),
      summary: asStr(p.summary) || asStr(p.question) || asStr(p.reason) || "Elevated to Tier-3", status: acked ? "with Tier-3" : "waiting for Tier-3", owner: null });
  }
  for (const c of conts) {
    const p = c.request.payload as { target?: string; containment_type?: string; reason?: string };
    items.push({ ev: c.request, key: `c:${c.seq}`, kind: "containment", seq: c.seq, at: c.request.occurred_at ?? null, by: c.request.actor_id, byRole: c.request.role, host: asStr(p.target),
      summary: `${asStr(p.containment_type) || "isolate"} ${asStr(p.target)}${asStr(p.reason) ? `: ${asStr(p.reason)}` : ""}`, status: c.status === "pending" ? "waiting for your approval" : c.status, owner: c.decidedBy });
  }
  items.sort((a, b) => b.seq - a.seq);
  const waiting = items.filter(i => ["waiting", "waiting for Tier-3", "waiting for your approval"].includes(i.status)).length;

  const statusTone = (s: string) => s.startsWith("waiting") ? "border-neon-amber/50 bg-neon-amber/10 text-neon-amber"
    : s === "resolved" || s === "executed" || s === "approved" ? "border-neon-green/40 bg-neon-green/10 text-neon-green"
      : s === "bounced" || s === "denied" ? "border-border text-slate-400" : "border-cyber-500/40 bg-cyber-500/10 text-cyber-200";
  const Icon = (k: EscalationItem["kind"]) => (k === "containment" ? ShieldAlert : k === "elevation" ? ArrowUpRight : Siren);

  return (
    <Card>
      <div className="flex items-center gap-2">
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-neon-amber" aria-hidden /> All escalations ({items.length})</h3>
        {waiting > 0 && <span className="rounded-full bg-neon-amber/15 px-2 font-mono text-[10px] text-neon-amber">{waiting} waiting</span>}
      </div>
      <p className="mt-1 text-[11px] text-slate-400">Everything the team raised: escalations to Tier-2, elevations to Tier-3 and containment requests. Open one to read the analyst&apos;s own words, then translate it for the business.</p>
      {items.length === 0 && <p className="mt-3 text-xs text-slate-500">No escalations yet. They appear here the moment an analyst raises one.</p>}
      <ul className="mt-2 space-y-1.5">
        {items.map(it => {
          const I = Icon(it.kind);
          const p = it.ev.payload as Record<string, unknown>;
          const eid = asStr(p.event_id);
          const rep = reports.filter(r => asStr((r.payload as { event_id?: unknown }).event_id) === eid).pop();
          const adv = it.kind === "containment" ? advice.filter(a => Number((a.payload as { request_seq?: unknown }).request_seq) === it.seq) : [];
          const isOpen = open === it.key;
          return (
            <li key={it.key} className="rounded-lg border border-border bg-bg">
              <button type="button" onClick={() => setOpen(isOpen ? null : it.key)} aria-expanded={isOpen} className="flex w-full items-start gap-2 px-2.5 py-2 text-left">
                <I className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-xs text-slate-100"><bdi>{it.summary}</bdi></span>
                  <span className="block text-[10px] text-slate-500">
                    <bdi>{nameOf(it.by)}</bdi> ({ROLE[it.byRole ?? ""] ?? "analyst"}){it.host && <> · <bdi className="font-mono">{it.host}</bdi></>}{it.at && <> · {fmtAgo(now - Date.parse(it.at))}</>}{it.owner && <> · owner <bdi>{nameOf(it.owner)}</bdi></>}
                  </span>
                </span>
                <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase ${statusTone(it.status)}`}>{it.status}</span>
              </button>
              {isOpen && (
                <div className="space-y-1.5 border-t border-border/60 px-2.5 py-2 text-[11px]">
                  {(asStr(p.observations) || asStr(p.why)) && <p className="text-slate-300"><span className="text-slate-500">What the analyst saw: </span>{asStr(p.observations) || asStr(p.why)}</p>}
                  {asStr(p.assessment) && <p className="text-slate-300"><span className="text-slate-500">Assessment: </span>{asStr(p.assessment)}</p>}
                  {asStr(p.severity) && <p className="text-slate-400">Severity given: {asStr(p.severity)}</p>}
                  {rep && <p className="text-slate-300"><span className="text-slate-500">Tier-2 report ({nameOf(rep.actor_id)}): </span>{asStr((rep.payload as { verdict?: unknown }).verdict).replace("_", " ")}{asStr((rep.payload as { summary?: unknown }).summary) && <> · {asStr((rep.payload as { summary?: unknown }).summary)}</>}</p>}
                  {adv.map(a => <p key={a.seq} className={(a.payload as { stance?: unknown }).stance === "object" ? "text-neon-amber" : "text-neon-green"}><bdi>{nameOf(a.actor_id)}</bdi> ({ROLE[a.role ?? ""] ?? "analyst"}) {(a.payload as { stance?: unknown }).stance === "object" ? "objects" : "supports"}{asStr((a.payload as { reason?: unknown }).reason) && <>: &quot;{asStr((a.payload as { reason?: unknown }).reason)}&quot;</>}</p>)}
                  <button type="button" onClick={() => onAddToReport(it.host, it.summary)} className="flex items-center gap-1 text-cyber-300 hover:underline"><FilePlus2 className="h-3.5 w-3.5" aria-hidden /> Add to the stakeholder report</button>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

/** How many escalations wait for someone (for the menu badge). */
export function waitingEscalations(events: Ev[]): number {
  let n = 0;
  for (const st of escalationStates(events).values()) if (st.rounds && !st.acked && !st.bounced && !st.resolved) n++;
  n += containmentRequests(events).filter(c => c.status === "pending").length;
  return n;
}
