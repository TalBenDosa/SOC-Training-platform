"use client";
import { useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/Button";
import { FileText, X } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { containmentRequests, escalationStates, isolationState } from "@/lib/team/projections";

/**
 * The incident report to stakeholders: the SOC Manager's structured update to the CISO, the
 * executives, Legal or the business owner, in business language. Prefilled from what the team
 * really did (escalated hosts, approved containments, isolations); the manager edits and sends.
 * Shape follows common incident-notification templates (NIST SP 800-61r3 communications,
 * CISA incident reporting fields): what happened, business impact, data, actions, what is known
 * and not yet known, what we need from you, and the time of the next update.
 */

export const AUDIENCES = [
  { v: "ciso", label: "CISO" }, { v: "executives", label: "Executive management" }, { v: "legal", label: "Legal & privacy" },
  { v: "business_owner", label: "Business owner" }, { v: "all", label: "All stakeholders" },
] as const;
export const STATUSES = [
  { v: "investigating", label: "Investigating" }, { v: "contained", label: "Contained" }, { v: "eradicated", label: "Eradicated" },
  { v: "recovering", label: "Recovering" }, { v: "closed", label: "Closed" },
] as const;
export const DATA_IMPACT = [
  { v: "none_known", label: "No evidence of data impact so far" }, { v: "suspected", label: "Suspected, under investigation" }, { v: "confirmed", label: "Confirmed" },
] as const;

export interface ReportSeed { hosts: string[]; lines: string[] }

export function StakeholderReportModal({ events, severity, seed, onClose, act }: { events: Ev[]; severity: number | null; seed: ReportSeed; onClose: () => void; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const ref = useRef<HTMLDivElement>(null);
  useFocusTrap(true, ref, { onEscape: onClose });
  const sent = events.filter(e => e.type === "stakeholder.report_sent");

  // Prefill from what really happened in the session.
  const pre = useMemo(() => {
    const hosts = new Set<string>(seed.hosts.filter(Boolean));
    for (const st of escalationStates(events).values()) {
      const p = st.request.payload as { hostname?: unknown; snapshot?: { hostname?: unknown } };
      const h = asStr(p.hostname) || asStr(p.snapshot?.hostname);
      if (st.rounds && h) hosts.add(h);
    }
    const actions: string[] = [];
    for (const c of containmentRequests(events)) {
      const p = c.request.payload as { target?: unknown; containment_type?: unknown };
      if (c.status === "approved" || c.status === "executed") actions.push(`${asStr(p.containment_type) || "isolate"} ${asStr(p.target)} (${c.status})`);
      if (asStr(p.target)) hosts.add(asStr(p.target));
    }
    for (const h of isolationState(events).values()) if (h.isolated) { actions.push(`${h.host} isolated in EDR`); hosts.add(h.host); }
    return { hosts: [...hosts].slice(0, 12), actions: [...new Set(actions)].join("; ") };
  }, [events, seed.hosts]);

  const [f, setF] = useState({
    audience: "ciso", status: "investigating", title: "", what_happened: seed.lines.join(". "), business_impact: "",
    affected: pre.hosts.join(", "), data_impact: "none_known", data_types: "", actions_taken: pre.actions,
    known: "", unknown: "", asks: "", next_update_min: "30",
  });
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => setF(s => ({ ...s, [k]: e.target.value }));
  const words = (t: string) => t.trim().split(/\s+/).filter(Boolean).length;
  const missing = [
    !f.title.trim() && "a title",
    words(f.what_happened) < 8 && "what happened (8+ words)",
    words(f.business_impact) < 4 && "the business impact",
    words(f.actions_taken) < 3 && "the actions taken",
    !f.unknown.trim() && "what is not known yet",
    !/^\d{1,3}$/.test(f.next_update_min) && "the next update time",
  ].filter(Boolean) as string[];

  async function send() {
    if (missing.length || busy) return;
    setBusy(true);
    const ok = await act("stakeholder.report_sent", {
      ...f, severity, next_update_min: Number(f.next_update_min),
      affected: f.affected.split(/[,\n]/).map(x => x.trim()).filter(Boolean).slice(0, 30),
    });
    setBusy(false);
    if (ok) onClose();
  }

  const field = "w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none";
  const label = "text-[11px] font-semibold text-slate-300";
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 px-4 py-8" onClick={onClose}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="sh-report-title" onClick={e => e.stopPropagation()}
        className="w-full max-w-2xl space-y-3 rounded-xl border border-border bg-bg-elevated p-4 shadow-2xl">
        <div className="flex items-center justify-between gap-2">
          <h2 id="sh-report-title" className="flex items-center gap-2 text-base font-semibold text-white"><FileText className="h-4 w-4 text-neon-purple" aria-hidden /> Incident report to stakeholders</h2>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded p-1 text-slate-400 hover:bg-white/5 hover:text-white"><X className="h-4 w-4" /></button>
        </div>
        <p className="text-[11px] text-slate-400">Business language, no jargon. Say what is confirmed and what is not, never more than you know. {severity ? <>Severity: <b className="text-slate-200">Sev-{severity}</b> (from your declaration).</> : <span className="text-neon-amber">Declare the incident first: the report carries its severity.</span>}</p>

        <div className="grid gap-2 sm:grid-cols-3">
          <label className="space-y-1"><span className={label}>To</span>
            <select id="sh-audience" value={f.audience} onChange={set("audience")} className={field}>{AUDIENCES.map(a => <option key={a.v} value={a.v}>{a.label}</option>)}</select></label>
          <label className="space-y-1"><span className={label}>Status</span>
            <select id="sh-status" value={f.status} onChange={set("status")} className={field}>{STATUSES.map(a => <option key={a.v} value={a.v}>{a.label}</option>)}</select></label>
          <label className="space-y-1"><span className={label}>Next update in (min)</span>
            <input id="sh-next" inputMode="numeric" value={f.next_update_min} onChange={set("next_update_min")} className={field} /></label>
        </div>
        <label className="block space-y-1"><span className={label}>Title</span>
          <input id="sh-title" value={f.title} maxLength={140} onChange={set("title")} placeholder="e.g. Suspected intrusion on finance workstations" className={field} /></label>
        <label className="block space-y-1"><span className={label}>What happened</span>
          <textarea id="sh-what" value={f.what_happened} rows={3} maxLength={1500} onChange={set("what_happened")} placeholder="In plain words: what was detected, when, and how far it reached so far." className={field} /></label>
        <label className="block space-y-1"><span className={label}>Business impact</span>
          <textarea id="sh-impact" value={f.business_impact} rows={2} maxLength={800} onChange={set("business_impact")} placeholder="Which services or teams are affected, who cannot work, workarounds in place." className={field} /></label>
        <label className="block space-y-1"><span className={label}>Affected systems</span>
          <input id="sh-affected" value={f.affected} maxLength={600} onChange={set("affected")} placeholder="Host names, comma separated" className={`${field} font-mono text-xs`} /></label>
        <div className="grid gap-2 sm:grid-cols-2">
          <label className="space-y-1"><span className={label}>Personal data</span>
            <select id="sh-data" value={f.data_impact} onChange={set("data_impact")} className={field}>{DATA_IMPACT.map(a => <option key={a.v} value={a.v}>{a.label}</option>)}</select></label>
          <label className="space-y-1"><span className={label}>Data types (if any)</span>
            <input id="sh-datatypes" value={f.data_types} maxLength={200} onChange={set("data_types")} placeholder="e.g. customer contact details" className={field} /></label>
        </div>
        <label className="block space-y-1"><span className={label}>Actions taken</span>
          <textarea id="sh-actions" value={f.actions_taken} rows={2} maxLength={800} onChange={set("actions_taken")} placeholder="Containment, isolations, blocks, accounts reset." className={field} /></label>
        <div className="grid gap-2 sm:grid-cols-2">
          <label className="space-y-1"><span className={label}>What we know</span>
            <textarea id="sh-known" value={f.known} rows={2} maxLength={600} onChange={set("known")} className={field} /></label>
          <label className="space-y-1"><span className={label}>What we do not know yet</span>
            <textarea id="sh-unknown" value={f.unknown} rows={2} maxLength={600} onChange={set("unknown")} className={field} /></label>
        </div>
        <label className="block space-y-1"><span className={label}>What we need from you</span>
          <input id="sh-asks" value={f.asks} maxLength={400} onChange={set("asks")} placeholder="Decisions or approvals (e.g. approve downtime of the payment server)" className={field} /></label>

        {missing.length > 0 && <p className="text-[11px] text-slate-500">Still needed: {missing.join(", ")}.</p>}
        <div className="flex items-center gap-2">
          <Button variant="primary" size="sm" disabled={busy || missing.length > 0 || !severity} onClick={send}>Send report</Button>
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
          {sent.length > 0 && <span className="ml-auto text-[11px] text-slate-500">{sent.length} report{sent.length > 1 ? "s" : ""} sent this shift</span>}
        </div>
      </div>
    </div>
  );
}
