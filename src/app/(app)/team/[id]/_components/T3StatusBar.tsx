"use client";
import { useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ArrowRight, Clock, ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { useServerNow } from "@/lib/team/clock";
import { buildRegister, nextStep, PHASE_LABEL, PHASE_ORDER, readinessBlockers, readinessOf, scansOf, updateDueMs, type NextStep, type Verdict } from "@/lib/team/t3Case";
import { ChoiceGroup } from "./ChoiceGroup";
import { t3Waiting } from "@/lib/team/t3Work";

/**
 * Tier-3 status bar (T3 interface spec, stage A): where the case stands, the one thing to do
 * next, and how long until the update promised to the SOC Manager is due.
 */
export function T3StatusBar({ events, feed = [], meId, pendingHandoffs, onGo }: {
  events: Ev[]; feed?: Ev[]; meId: string; pendingHandoffs: number; onGo: (step: NextStep) => void;
}) {
  const step = useMemo(() => {
    const w = t3Waiting(events, feed);
    return nextStep(events, { pendingHandoffs, leadHost: w.lead?.host ?? null, consults: w.consults, reviews: w.reviews });
  }, [events, feed, pendingHandoffs]);
  const due = useMemo(() => updateDueMs(events, meId), [events, meId]);
  const now = useServerNow(due ? 5_000 : 30_000);
  const left = due ? Math.round((due - now) / 1000) : null;
  const tone = left == null ? "" : left < 0 ? "text-severity-high" : left < 120 ? "text-neon-amber" : "text-neon-green";
  const mmss = (s: number) => `${Math.floor(Math.abs(s) / 60)}:${String(Math.abs(s) % 60).padStart(2, "0")}`;
  const idx = PHASE_ORDER.indexOf(step.phase);
  return (
    <div data-tour="t3-status" className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-border bg-bg-elevated/80 px-3 py-2">
      <div className="flex items-center gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Case</span>
        <span className="text-xs font-semibold text-white">{PHASE_LABEL[step.phase]}</span>
        <span className="flex gap-1" aria-hidden>
          {PHASE_ORDER.map((p, i) => <span key={p} className={`h-1.5 w-4 rounded-full ${i <= idx ? "bg-cyber-400" : "bg-slate-700"}`} />)}
        </span>
      </div>
      <button type="button" onClick={() => onGo(step)} className="group flex min-w-0 flex-1 items-center gap-2 rounded-md border border-cyber-500/30 bg-cyber-500/10 px-2.5 py-1 text-left text-xs text-cyber-100 hover:border-cyber-400/60">
        <span className="shrink-0 text-[11px] font-semibold uppercase tracking-wider text-cyber-300">Next</span>
        <span className="min-w-0 flex-1">{step.text}</span>
        <ArrowRight className="h-3.5 w-3.5 shrink-0 transition-transform group-hover:translate-x-0.5" aria-hidden />
      </button>
      {left != null && (
        <span className={`flex items-center gap-1 text-xs tabular-nums ${tone}`} title="The next update you promised the SOC Manager">
          <Clock className="h-3.5 w-3.5" aria-hidden />
          {left < 0 ? `Update to the manager overdue by ${mmss(left)}` : `Update to the manager due in ${mmss(left)}`}
        </span>
      )}
    </div>
  );
}

/**
 * The containment-readiness verdict (stage B). The blockers are derived from the scope register;
 * signing READY over open blockers is allowed but needs a reason, and says so.
 */
export function T3ReadinessCard({ events, nameOf, act, onReport }: {
  events: Ev[]; nameOf: (u: string | null) => string;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>; onReport: () => void;
}) {
  const register = useMemo(() => buildRegister(events), [events]);
  const scans = useMemo(() => scansOf(events), [events]);
  const blockers = useMemo(() => readinessBlockers(events, register, scans), [events, register, scans]);
  const hard = blockers.filter(b => b.severity === "block");
  const verdicts = useMemo(() => readinessOf(events), [events]);
  const last = verdicts[verdicts.length - 1] ?? null;
  const lastChange = Math.max(0, ...register.map(r => r.seq), ...scans.map(s => s.seq));
  const stale = !!last && last.seq < lastChange;
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const suggested: Verdict = hard.length ? "not_ready" : "ready";
  async function sign() {
    const v = verdict ?? suggested;
    const r = reason.trim();
    if (r.length < 5) { setErr("Give the manager a reason (at least 5 characters)."); return; }
    setErr(null); setBusy(true);
    const ok = await act("t3.readiness", { verdict: v, blockers: hard.map(b => b.text).slice(0, 20), reason: r.slice(0, 400) });
    setBusy(false);
    if (ok) { setReason(""); setVerdict(null); }
  }
  const Icon = last?.verdict === "ready" ? ShieldCheck : last?.verdict === "not_ready" ? ShieldAlert : ShieldQuestion;
  return (
    <Card className={hard.length ? "border-neon-amber/30" : "border-neon-green/30"} >
      <div data-tour="t3-readiness">
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Icon className="h-4 w-4 text-cyber-300" aria-hidden /> Containment readiness</h3>
        {last ? (
          <p className="mt-1 text-[11px] text-slate-300">
            Signed <strong className="text-white">{last.verdict === "ready" ? "READY" : last.verdict === "not_ready" ? "NOT READY" : "CANNOT TELL"}</strong> by {nameOf(last.by)}: {last.reason}
            {stale && <span className="ml-1 text-neon-amber">The register changed since: sign again.</span>}
          </p>
        ) : <p className="mt-1 text-[11px] text-slate-400">Tell the SOC Manager whether it is safe to contain now, and what is still in the way.</p>}
        {blockers.length > 0 ? (
          <ul className="mt-2 space-y-1">
            {blockers.map(b => <li key={b.id} className={`text-[11px] ${b.severity === "block" ? "text-neon-amber" : "text-slate-300"}`}>{b.severity === "block" ? "Blocking: " : "Note: "}{b.text}</li>)}
          </ul>
        ) : <p className="mt-2 text-[11px] text-neon-green">Nothing blocking: every entity is confirmed, cleared or marked cannot check, and the scope has been swept.</p>}
        <div className="mt-2 space-y-2">
          <ChoiceGroup legend="Verdict" options={[{ value: "ready", label: "Ready to contain" }, { value: "not_ready", label: "Not yet" }, { value: "unknown", label: "Cannot tell" }]} value={verdict ?? suggested} onChange={setVerdict} size="xs" />
          {(verdict ?? suggested) === "ready" && hard.length > 0 && <p className="text-[11px] text-neon-amber">Signing with open blockers: say why it is safe anyway.</p>}
          <label className="block text-[11px] text-slate-400">Reason for the manager
            <input value={reason} onChange={e => setReason(e.target.value)} maxLength={400} placeholder={hard.length ? "e.g. WS-FIN-2851 still suspected, sweeping it now" : "e.g. scope confirmed: 2 hosts, memory captured on both"} className="mt-1 w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          </label>
          {err && <p role="alert" className="text-[11px] text-neon-amber">{err}</p>}
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" size="sm" disabled={busy} onClick={() => void sign()}>Sign verdict</Button>
            <Button variant="outline" size="sm" onClick={onReport}>Report to the manager</Button>
          </div>
        </div>
      </div>
    </Card>
  );
}
