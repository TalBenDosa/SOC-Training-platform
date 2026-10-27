"use client";
import { Fragment, useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Siren, ShieldAlert, ArrowUpRight, FilePlus2 } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { escalationStates, containmentRequests } from "@/lib/team/projections";
import { useServerNow } from "@/lib/team/clock";
import { TeamImageThumb, imagesOf } from "./teamImages";

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

const VERDICT: Record<string, string> = { true_positive: "true positive", suspicious: "suspicious", benign: "benign", false_positive: "false positive", escalate: "escalate" };
const verdictText = (v: unknown) => VERDICT[asStr(v)] ?? asStr(v).replace(/_/g, " ");

/** One labelled line of the investigation; nothing is rendered for an empty value. */
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  if (children == null || children === "" || children === false) return null;
  return <p className="text-slate-300"><span className="text-slate-500">{label}: </span>{children}</p>;
}

/** The fields of the log the analyst escalated, as they saw it. */
function OriginalLog({ snap }: { snap: Record<string, unknown> }) {
  const proc = (snap.process ?? {}) as { name?: unknown; cmdline?: unknown };
  const file = (snap.file ?? {}) as { path?: unknown; sha256?: unknown };
  const rows: [string, string][] = ([
    ["Source", [asStr(snap.vendor), asStr(snap.source)].filter(Boolean).join(" · ")],
    ["Time", asStr(snap.ts).replace("T", " ").slice(0, 19)], ["Event", asStr(snap.event_type)], ["Severity", asStr(snap.severity)], ["Host", asStr(snap.hostname)],
    ["User", asStr(snap.user_email) || asStr((snap.user as { email?: unknown } | undefined)?.email)],
    ["Source IP", asStr(snap.src_ip)], ["Destination IP", asStr(snap.dst_ip)],
    ["Process", asStr(proc.name)], ["Command line", asStr(proc.cmdline)], ["File", asStr(file.path)], ["SHA256", asStr(file.sha256)],
    ["Description", asStr(snap.description)],
  ] as [string, string][]).filter(([, v]) => v);
  return (
    <details className="rounded border border-border/60 px-2 py-1">
      <summary className="cursor-pointer text-slate-400">The original log</summary>
      <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5">
        {rows.map(([k, v]) => <Fragment key={k}><dt className="text-slate-500">{k}</dt><dd className="break-all font-mono text-slate-200"><bdi>{v}</bdi></dd></Fragment>)}
      </dl>
      {snap.raw != null && (
        <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-bg-elevated p-1.5 font-mono text-[10px] text-slate-400">{typeof snap.raw === "string" ? snap.raw : JSON.stringify(snap.raw, null, 2)}</pre>
      )}
    </details>
  );
}

export function EscalationsPanel({ events, nameOf, onAddToReport, sessionId }: { events: Ev[]; nameOf: (u: string | null) => string; onAddToReport: (host: string, line: string) => void; sessionId?: string }) {
  const now = useServerNow(15_000);
  const [open, setOpen] = useState<string | null>(null);
  const feedById = useMemo(() => new Map(events.filter(e => e.type === "feed.event").map(e => [asStr((e.payload as { id?: unknown }).id), e.payload as Record<string, unknown>])), [events]);
  const states = useMemo(() => escalationStates(events), [events]);
  const conts = useMemo(() => containmentRequests(events), [events]);
  const reports = useMemo(() => events.filter(e => e.type === "report.submitted"), [events]);
  const advice = useMemo(() => events.filter(e => e.type === "containment.advised"), [events]);
  // Tier-1's own determination on the log (the latest verdict) and any bounce back from Tier-2.
  const verdictByEid = useMemo(() => { const m = new Map<string, Ev>(); for (const e of events) if (e.type === "disposition.set") m.set(asStr((e.payload as { event_id?: unknown }).event_id), e); return m; }, [events]);
  const bounces = useMemo(() => events.filter(e => e.type === "escalation.bounced"), [events]);

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
  const waiting = waitingEscalations(events);

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
                  {/* Every investigation parameter the analyst sent (Tal, 2026-10-27: the manager saw only a short line). */}
                  {it.kind === "escalation" && (() => {
                    const disp = verdictByEid.get(eid);
                    const dp = (disp?.payload ?? {}) as { verdict?: unknown; note?: unknown };
                    const iocs = Array.isArray(p.iocs) ? (p.iocs as { type?: unknown; value?: unknown }[]) : [];
                    const shots = imagesOf(p.images);
                    const snap = (p.snapshot && typeof p.snapshot === "object" ? p.snapshot : null) as Record<string, unknown> | null;
                    const conf = typeof p.confidence === "number" ? Math.round((p.confidence as number) * 100) : null;
                    return (
                      <>
                        <Field label="Summary"><bdi>{asStr(p.summary) || asStr(p.what)}</bdi></Field>
                        {disp && <Field label={`Tier-1 determination (${nameOf(disp.actor_id)})`}><b className="text-slate-100">{verdictText(dp.verdict)}</b>{asStr(dp.note) && <>: <bdi>{asStr(dp.note)}</bdi></>}</Field>}
                        <Field label="What the analyst saw"><bdi>{asStr(p.observations) || asStr(p.why)}</bdi></Field>
                        <Field label="Assessment"><bdi>{asStr(p.assessment)}</bdi></Field>
                        <Field label="Severity given">{asStr(p.severity)}</Field>
                        <Field label="Requested action">{asStr(p.requested_action).replace(/[-_]/g, " ")}</Field>
                        <Field label="Confidence">{p.low_confidence ? "low: a lead sent for a second look" : conf != null ? `${conf}%` : ""}</Field>
                        <Field label="Affected">{[asStr(p.hostname), asStr(p.entity) !== asStr(p.hostname) ? asStr(p.entity) : ""].filter(Boolean).join(" · ")}</Field>
                        {iocs.length > 0 && <Field label={`IOCs (${iocs.length})`}><span className="inline-flex flex-wrap gap-1">{iocs.map((i, k) => <span key={k} className="rounded border border-border px-1 font-mono text-[10px] text-slate-200"><bdi>{asStr(i.type) ? `${asStr(i.type)}: ` : ""}{asStr(i.value)}</bdi></span>)}</span></Field>}
                        {shots.length > 0 && sessionId && <div className="flex flex-wrap gap-1.5">{shots.map((img, k) => <TeamImageThumb key={img.path} sessionId={sessionId} image={img} alt={`Screenshot ${k + 1} with this escalation`} className="max-h-24" />)}</div>}
                        {snap && <OriginalLog snap={snap} />}
                        {bounces.filter(b => asStr((b.payload as { event_id?: unknown }).event_id) === eid).map(b => <Field key={b.seq} label={`Bounced back by ${nameOf(b.actor_id)}`}><bdi>{asStr((b.payload as { reason?: unknown }).reason)}</bdi></Field>)}
                      </>
                    );
                  })()}
                  {it.kind === "elevation" && (
                    <>
                      <Field label="Summary"><bdi>{asStr(p.summary)}</bdi></Field>
                      <Field label="What Tier-3 is asked to hunt"><bdi>{asStr(p.hunt_ask)}</bdi></Field>
                      <Field label="Tier-2 verdict">{p.t2_verdict ? verdictText(p.t2_verdict) : ""}</Field>
                      <Field label="Tier-2 findings"><bdi>{asStr(p.t2_findings)}</bdi></Field>
                      <Field label="Tier-2 recommendation"><bdi>{asStr(p.t2_recommendation)}</bdi></Field>
                      <Field label="Severity">{asStr(p.severity)}</Field>
                      {Array.isArray(p.iocs) && (p.iocs as unknown[]).length > 0 && <Field label="IOCs"><span className="font-mono text-[10px]">{(p.iocs as { type?: unknown; value?: unknown }[]).map(i => asStr(i.value)).join(", ")}</span></Field>}
                    </>
                  )}
                  {it.kind === "containment" && (
                    <>
                      <Field label="Action">{`${asStr(p.containment_type).replace(/_/g, " ") || "isolate host"} on ${asStr(p.target)}`}</Field>
                      <Field label="Why"><bdi>{asStr(p.reason)}</bdi></Field>
                      <Field label="Asset criticality">{asStr(p.asset_criticality)}</Field>
                      <Field label="Blast radius (who is affected)"><bdi>{asStr(p.blast_radius)}</bdi></Field>
                      <Field label="Business owner"><bdi>{asStr(p.business_owner)}</bdi></Field>
                      <Field label="Incident"><bdi>{asStr(p.incident)}</bdi></Field>
                    </>
                  )}
                  {rep && (() => {
                    const rp = rep.payload as { verdict?: unknown; summary?: unknown; findings?: unknown; recommendation?: unknown; incident?: unknown };
                    return (
                      <div className="rounded border border-cyber-500/30 bg-cyber-500/[0.04] px-2 py-1.5">
                        <p className="font-semibold text-cyber-200">Tier-2 report ({nameOf(rep.actor_id)})</p>
                        <Field label="Verdict"><b className="text-slate-100">{verdictText(rp.verdict)}</b></Field>
                        <Field label="Summary"><bdi>{asStr(rp.summary)}</bdi></Field>
                        <Field label="Findings"><bdi>{asStr(rp.findings)}</bdi></Field>
                        <Field label="Recommendation"><bdi>{asStr(rp.recommendation)}</bdi></Field>
                        <Field label="Incident"><bdi>{asStr(rp.incident)}</bdi></Field>
                      </div>
                    );
                  })()}
                  {adv.map(a => <p key={a.seq} className={(a.payload as { stance?: unknown }).stance === "object" ? "text-neon-amber" : "text-neon-green"}><bdi>{nameOf(a.actor_id)}</bdi> ({ROLE[a.role ?? ""] ?? "analyst"}) {(a.payload as { stance?: unknown }).stance === "object" ? "objects" : "supports"}{asStr((a.payload as { reason?: unknown }).reason) && <>: &quot;{asStr((a.payload as { reason?: unknown }).reason)}&quot;</>}</p>)}
                  {it.kind === "containment" && it.status.startsWith("waiting") && <p className="text-neon-amber">Approve or deny it in Containment approvals, at the top of this view.</p>}
                  <button type="button" onClick={() => {
                    const t1 = verdictByEid.get(eid); const t2 = rep ? (rep.payload as { verdict?: unknown }).verdict : null;
                    const calls = [t1 ? `Tier-1: ${verdictText((t1.payload as { verdict?: unknown }).verdict)}` : "", t2 ? `Tier-2: ${verdictText(t2)}` : ""].filter(Boolean).join("; ");
                    onAddToReport(it.host, calls ? `${it.summary} (${calls})` : it.summary);
                  }} className="flex items-center gap-1 text-cyber-300 hover:underline"><FilePlus2 className="h-3.5 w-3.5" aria-hidden /> Add to the stakeholder report</button>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

/** Escalations nobody has taken yet: Tier-1 to Tier-2 and Tier-2 to Tier-3 (not your approvals). */
export function waitingForTeam(events: Ev[]): number {
  let n = 0;
  for (const st of escalationStates(events).values()) if (st.rounds && !st.acked && !st.bounced && !st.resolved) n++;
  for (const e of events) {
    if (e.type !== "elevation.requested") continue;
    const eid = asStr((e.payload as { event_id?: unknown }).event_id);
    if (!events.some(x => x.type === "elevation.acknowledged" && x.seq > e.seq && asStr((x.payload as { event_id?: unknown }).event_id) === eid)) n++;
  }
  return n;
}
/** Containment requests waiting for the SOC Manager's approval. */
export function pendingApprovals(events: Ev[]): number {
  return containmentRequests(events).filter(c => c.status === "pending").length;
}
/** Everything in the Escalations view that is waiting (the menu badge and the panel use this one count). */
export function waitingEscalations(events: Ev[]): number {
  return waitingForTeam(events) + pendingApprovals(events);
}
