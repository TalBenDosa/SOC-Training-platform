"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { FileText, X } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { useServerNow } from "@/lib/team/clock";
import { containmentRequests, escalationStates, isolationState } from "@/lib/team/projections";

/**
 * The incident report to stakeholders: the SOC Manager's structured update to the CISO, the
 * executives, Legal or the business owner, in business language. Prefilled from what the team
 * really did (escalated hosts, approved containments, isolations); the manager edits and sends.
 * Shape follows common incident-notification templates (NIST SP 800-61r3 communications,
 * CISA incident reporting fields): what happened, business impact, data, actions, what is known
 * and not yet known, what we need from you, and the time of the next update.
 *
 * Safe by design: the draft survives closing the form, a click outside never discards it,
 * closing with changes asks first, and sending confirms what was promised.
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
const AUD_LABEL: Record<string, string> = Object.fromEntries(AUDIENCES.map(a => [a.v, a.label]));
const NEXT_CHOICES = ["15", "30", "60"] as const;

export interface ReportSeed { hosts: string[]; lines: string[] }
export interface ReportDraft {
  audience: string; status: string; title: string; what_happened: string; business_impact: string; affected: string;
  data_impact: string; data_types: string; actions_taken: string; known: string; unknown: string; asks: string; next_update_min: string;
}

/** A containment, in business words (no tool jargon). */
function plainAction(type: string, target: string, status: string): string {
  const what = type === "disable_account" ? `${target} account disabled` : type === "block_indicator" ? `${target} blocked` : `${target} cut off from the network`;
  return `${what}${status === "executed" ? "" : " (approved, being carried out)"}`;
}

export function StakeholderReportModal({ events, severity, seed, onClose, act, draft, onDraft, onSent }: {
  events: Ev[]; severity: number | null; seed: ReportSeed; onClose: () => void; act: (t: string, p: Record<string, unknown>) => Promise<boolean>;
  draft?: ReportDraft | null; onDraft?: (d: ReportDraft) => void; onSent?: (msg: string) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const now = useServerNow(15_000);

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
      if (c.status === "approved" || c.status === "executed") actions.push(plainAction(asStr(p.containment_type), asStr(p.target), c.status));
      if (asStr(p.target)) hosts.add(asStr(p.target));
    }
    for (const h of isolationState(events).values()) if (h.isolated) { actions.push(`${h.host} cut off from the network`); hosts.add(h.host); }
    return { hosts: [...hosts].slice(0, 12), actions: [...new Set(actions)].join("; ") };
  }, [events, seed.hosts]);

  const initial: ReportDraft = draft ?? {
    audience: "ciso", status: "investigating", title: "", what_happened: seed.lines.join(". "), business_impact: "",
    affected: pre.hosts.join(", "), data_impact: "none_known", data_types: "", actions_taken: pre.actions,
    known: "", unknown: "", asks: "", next_update_min: "",
  };
  const [f, setF] = useState<ReportDraft>(() => {
    // A case added from Escalations joins the saved draft instead of replacing it.
    if (!draft) return initial;
    const extraHosts = seed.hosts.filter(h => h && !draft.affected.includes(h));
    const extraLines = seed.lines.filter(l => l && !draft.what_happened.includes(l));
    return { ...draft, affected: [draft.affected, ...extraHosts].filter(Boolean).join(", "), what_happened: [draft.what_happened, ...extraLines].filter(Boolean).join(". ") };
  });
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const dirty = JSON.stringify(f) !== JSON.stringify(initial) || !!draft;
  useEffect(() => { onDraft?.(f); }, [f]); // eslint-disable-line react-hooks/exhaustive-deps

  const close = () => { onClose(); };   // the draft is kept by the page (onDraft), so closing never loses work
  useFocusTrap(true, ref, { onEscape: close });

  const set = (k: keyof ReportDraft) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => setF(s => ({ ...s, [k]: e.target.value }));
  const words = (t: string) => t.trim().split(/\s+/).filter(Boolean).length;
  const errors: Partial<Record<keyof ReportDraft, string>> = {
    ...(!f.title.trim() ? { title: "Give the report a short title." } : {}),
    ...(words(f.what_happened) < 8 ? { what_happened: "Say what happened in at least 8 words." } : {}),
    ...(words(f.business_impact) < 4 ? { business_impact: "Describe the impact on the business." } : {}),
    ...(words(f.actions_taken) < 3 ? { actions_taken: "List the actions taken so far." } : {}),
    ...(!f.unknown.trim() ? { unknown: "Say what is not known yet (there is always something)." } : {}),
    ...(!/^\d{1,3}$/.test(f.next_update_min) ? { next_update_min: "Choose when the next update comes: it is a promise you will be held to." } : {}),
  };
  const ok = Object.keys(errors).length === 0;

  async function send() {
    setTried(true);
    if (!ok || busy || !severity) return;
    setBusy(true);
    const sent = await act("stakeholder.report_sent", {
      ...f, severity, next_update_min: Number(f.next_update_min),
      affected: f.affected.split(/[,\n]/).map(x => x.trim()).filter(Boolean).slice(0, 30),
    });
    setBusy(false);
    if (sent) {
      const due = new Date(now + Number(f.next_update_min) * 60000);
      onSent?.(`Report sent to ${AUD_LABEL[f.audience] ?? f.audience}. You promised the next update by ${due.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.`);
      onClose();
    }
  }

  const field = "w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60";
  const label = "text-[11px] font-semibold text-slate-300";
  const err = (k: keyof ReportDraft) => tried && errors[k] ? <span id={`sh-err-${k}`} className="block text-[11px] text-neon-amber">{errors[k]}</span> : null;
  const aria = (k: keyof ReportDraft) => ({ "aria-invalid": tried && !!errors[k], "aria-describedby": tried && errors[k] ? `sh-err-${k}` : undefined });
  const req = <span className="text-neon-amber" aria-hidden>*</span>;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 px-4 py-8">
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="sh-report-title"
        className="w-full max-w-2xl space-y-4 rounded-xl border border-border bg-bg-elevated p-4 shadow-2xl">
        <div className="flex items-center justify-between gap-2">
          <h2 id="sh-report-title" className="flex items-center gap-2 text-base font-semibold text-white"><FileText className="h-4 w-4 text-neon-purple" aria-hidden /> Incident report to stakeholders</h2>
          <button type="button" onClick={close} aria-label="Close (your draft is kept)" title="Close (your draft is kept)" className="rounded p-1 text-slate-400 hover:bg-white/5 hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400"><X className="h-4 w-4" /></button>
        </div>
        <p className="text-[11px] text-slate-400">Business language, no jargon. Say what is confirmed and what is not, never more than you know. {severity ? <>Severity: <b className="text-slate-200">Sev-{severity}</b> (from your declaration).</> : <span className="text-neon-amber">Declare the incident first: the report carries its severity.</span>} Fields marked {req} are required.{dirty && " Closing keeps your draft."}</p>

        <section className="space-y-2" aria-labelledby="sh-sec-who">
          <h3 id="sh-sec-who" className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Who and when</h3>
          <div className="grid gap-2 sm:grid-cols-3">
            <label className="space-y-1"><span className={label}>To</span>
              <select id="sh-audience" value={f.audience} onChange={set("audience")} className={field}>{AUDIENCES.map(a => <option key={a.v} value={a.v}>{a.label}</option>)}</select></label>
            <label className="space-y-1"><span className={label}>Status</span>
              <select id="sh-status" value={f.status} onChange={set("status")} className={field}>{STATUSES.map(a => <option key={a.v} value={a.v}>{a.label}</option>)}</select></label>
            <fieldset className="space-y-1" {...aria("next_update_min")}>
              <legend className={label}>Next update in {req}</legend>
              <div className="flex gap-1">
                {NEXT_CHOICES.map(m => (
                  <label key={m} className="cursor-pointer">
                    <input type="radio" name="sh-next" value={m} checked={f.next_update_min === m} onChange={() => setF(s => ({ ...s, next_update_min: m }))} className="peer sr-only" />
                    <span className="block rounded border border-border px-2 py-1.5 text-xs text-slate-300 peer-checked:border-neon-purple/60 peer-checked:bg-neon-purple/15 peer-checked:text-white peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-cyber-400">{m} min</span>
                  </label>
                ))}
              </div>
              {err("next_update_min")}
            </fieldset>
          </div>
          <label className="block space-y-1"><span className={label}>Title {req}</span>
            <input id="sh-title" value={f.title} maxLength={140} onChange={set("title")} placeholder="e.g. Suspected intrusion on finance workstations" className={field} {...aria("title")} />{err("title")}</label>
        </section>

        <section className="space-y-2" aria-labelledby="sh-sec-what">
          <h3 id="sh-sec-what" className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">What happened and what it means</h3>
          <label className="block space-y-1"><span className={label}>What happened {req}</span>
            <textarea id="sh-what" value={f.what_happened} rows={3} maxLength={1500} onChange={set("what_happened")} placeholder="In plain words: what was detected, when, and how far it reached so far." className={field} {...aria("what_happened")} />{err("what_happened")}</label>
          <label className="block space-y-1"><span className={label}>Business impact {req}</span>
            <textarea id="sh-impact" value={f.business_impact} rows={2} maxLength={800} onChange={set("business_impact")} placeholder="Which services or teams are affected, who cannot work, workarounds in place." className={field} {...aria("business_impact")} />{err("business_impact")}</label>
          <label className="block space-y-1"><span className={label}>Affected systems</span>
            <input id="sh-affected" value={f.affected} maxLength={600} onChange={set("affected")} placeholder="Host names, comma separated" className={`${field} font-mono text-xs`} /></label>
          <div className="grid gap-2 sm:grid-cols-2">
            <label className="space-y-1"><span className={label}>Personal data</span>
              <select id="sh-data" value={f.data_impact} onChange={set("data_impact")} className={field}>{DATA_IMPACT.map(a => <option key={a.v} value={a.v}>{a.label}</option>)}</select></label>
            <label className="space-y-1"><span className={label}>Data types (if any)</span>
              <input id="sh-datatypes" value={f.data_types} maxLength={200} onChange={set("data_types")} placeholder="e.g. customer contact details" className={field} /></label>
          </div>
        </section>

        <section className="space-y-2" aria-labelledby="sh-sec-done">
          <h3 id="sh-sec-done" className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">What we did, what we know, what we need</h3>
          <label className="block space-y-1"><span className={label}>Actions taken {req}</span>
            <textarea id="sh-actions" value={f.actions_taken} rows={2} maxLength={800} onChange={set("actions_taken")} placeholder="Systems cut off from the network, accounts disabled, traffic blocked." className={field} {...aria("actions_taken")} />{err("actions_taken")}</label>
          <div className="grid gap-2 sm:grid-cols-2">
            <label className="space-y-1"><span className={label}>What we know</span>
              <textarea id="sh-known" value={f.known} rows={2} maxLength={600} onChange={set("known")} className={field} /></label>
            <label className="space-y-1"><span className={label}>What we do not know yet {req}</span>
              <textarea id="sh-unknown" value={f.unknown} rows={2} maxLength={600} onChange={set("unknown")} className={field} {...aria("unknown")} />{err("unknown")}</label>
          </div>
          <label className="block space-y-1"><span className={label}>What we need from you</span>
            <input id="sh-asks" value={f.asks} maxLength={400} onChange={set("asks")} placeholder="Decisions or approvals (e.g. approve downtime of the payment server)" className={field} /></label>
        </section>

        <div className="flex flex-wrap items-center gap-2 border-t border-border/60 pt-3">
          <Button variant="primary" size="sm" disabled={busy || !severity} onClick={send}>Send report</Button>
          <Button variant="ghost" size="sm" onClick={close}>Close, keep draft</Button>
          {tried && !ok && <span className="text-[11px] text-neon-amber" role="alert">{Object.keys(errors).length} field{Object.keys(errors).length > 1 ? "s" : ""} still needed (marked above).</span>}
        </div>
      </div>
    </div>
  );
}

/** Reporting view: the reports already sent, and whether each promised update was kept. */
export function ReportsSent({ events }: { events: Ev[] }) {
  const now = useServerNow(15_000);
  const sent = events.filter(e => e.type === "stakeholder.report_sent");
  if (!sent.length) return null;
  const updates = events.filter(e => e.type === "sitrep.sent" || e.type === "stakeholder.report_sent").map(e => (e.occurred_at ? Date.parse(e.occurred_at) : 0));
  const hhmm = (t: number) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><FileText className="h-4 w-4 text-neon-purple" aria-hidden /> Reports sent ({sent.length})</h3>
      <ul className="mt-2 space-y-1.5">
        {sent.slice().reverse().map(e => {
          const p = e.payload as Record<string, unknown>;
          const at = e.occurred_at ? Date.parse(e.occurred_at) : now;
          const due = at + (Number(p.next_update_min) || 0) * 60000;
          const kept = updates.some(u => u > at && u <= due + 60000);
          const state = kept ? { t: "next update kept", c: "text-neon-green" } : now > due ? { t: `next update was due ${hhmm(due)}`, c: "text-severity-critical" } : { t: `next update due ${hhmm(due)}`, c: "text-neon-amber" };
          return (
            <li key={e.seq} className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg px-2.5 py-1.5 text-xs">
              <span className="font-mono text-[11px] text-slate-400">{hhmm(at)}</span>
              <span className="text-slate-100"><bdi>{asStr(p.title) || "Incident report"}</bdi></span>
              <span className="text-slate-400">to {AUD_LABEL[asStr(p.audience)] ?? asStr(p.audience)}, {asStr(p.status)}</span>
              <span className={`ml-auto text-[11px] ${state.c}`}>{state.t}</span>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
