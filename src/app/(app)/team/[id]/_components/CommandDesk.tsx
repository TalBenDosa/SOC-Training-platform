"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Gavel, Megaphone, Phone, Mail, MessageSquare, User, Clock } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { useServerNow } from "@/lib/team/clock";
import { requestPhase, LATE_GRACE_S } from "@/lib/team/manager/timing";
import { ChoiceGroup } from "./ChoiceGroup";

/**
 * The SOC Manager's command desk: declare the incident and its severity, and decide the
 * decision cards the director raises from what is really happening in the session
 * (CISO / Legal / the business on one side, the manager's own analysts on the other).
 * Feedback (rank, the best option and why, the effect on the four impact indicators)
 * arrives from the server only after a card is decided or expires.
 */

type Rank = "great" | "good" | "okay" | "weak";
interface Indicators { continuity: number; trust: number; capacity: number; regulatory: number }
interface Feedback {
  inject_id: string; card: string; state: "open" | "answered" | "expired";
  option?: string | null; confidence?: string | null; rank?: Rank | null; best?: string; score?: number;
  notes?: Record<string, string>; delta?: Partial<Indicators>; objective?: string;
}
interface CardBody {
  inject_id: string; card: string; audience: string; pillar: string;
  from?: { name?: string; role?: string }; channel?: string; text?: string;
  options?: { id: string; label: string }[]; deadline_s?: number;
  /** The containment request this card is about (it is decided under Escalations). */
  about?: { target?: string };
}

const DIRECTOR_POLL_MS = 20_000;
const SEVERITY: { v: number; label: string; hint: string }[] = [
  { v: 1, label: "Sev-1", hint: "critical: data loss, critical asset, ransomware, spreading" },
  { v: 2, label: "Sev-2", hint: "high: confirmed compromise, contained to a few hosts" },
  { v: 3, label: "Sev-3", hint: "medium: suspicious activity, not yet confirmed" },
  { v: 4, label: "Sev-4", hint: "low: minor, no business impact" },
];
const RANK_STYLE: Record<Rank, string> = {
  great: "border-neon-green/50 bg-neon-green/10 text-neon-green",
  good: "border-cyber-500/50 bg-cyber-500/10 text-cyber-200",
  okay: "border-neon-amber/50 bg-neon-amber/10 text-neon-amber",
  weak: "border-severity-critical/50 bg-severity-critical/10 text-severity-critical",
};
const RANK_LABEL: Record<Rank, string> = { great: "Best call", good: "Good call", okay: "Acceptable", weak: "Costly call" };
const IND_LABEL: Record<keyof Indicators, string> = { continuity: "Business continuity", trust: "Stakeholder trust", capacity: "Team capacity", regulatory: "Regulatory exposure" };
const channelIcon = (c?: string) => (c === "call" ? Phone : c === "email" ? Mail : c === "chat" ? MessageSquare : User);
const fmtDelta = (d?: Partial<Indicators>) => Object.entries(d ?? {}).filter(([, v]) => v).map(([k, v]) => `${IND_LABEL[k as keyof Indicators]} ${Number(v) > 0 ? "+" : ""}${v}`).join(" · ");

export function CommandDesk({ sessionId, events, act, running, onOpenEscalations }: { sessionId: string; events: Ev[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; running: boolean; onOpenEscalations?: () => void }) {
  const now = useServerNow(1_000);
  const cards = useMemo(() => events.filter(e => e.type === "staff.inject" && asStr((e.payload as { kind?: unknown }).kind) === "decision"), [events]);
  const answered = useMemo(() => new Map(events.filter(e => e.type === "decision.answered").map(e => [asStr((e.payload as { inject_id?: unknown }).inject_id), e])), [events]);
  const declared = events.find(e => e.type === "incident.declared");
  const sevNow = [...events].reverse().find(e => e.type === "incident.declared" || e.type === "incident.severity_changed");
  const severity = sevNow ? Number((sevNow.payload as { severity?: unknown }).severity) : null;

  // ── The director: ask the server whether the session now warrants a card ──
  useEffect(() => {
    if (!running) return;
    let stop = false;
    const tick = () => { if (!stop && document.visibilityState === "visible") void fetch(`/api/team/sessions/${sessionId}/director`, { method: "POST" }).catch(() => {}); };
    const first = setTimeout(tick, 4_000);
    const iv = setInterval(tick, DIRECTOR_POLL_MS);
    return () => { stop = true; clearTimeout(first); clearInterval(iv); };
  }, [sessionId, running]);

  // ── Feedback for decided / expired cards ──
  const [fb, setFb] = useState<{ cards: Feedback[]; indicators: Indicators } | null>(null);
  const decidedCount = cards.filter(c => answered.has(asStr((c.payload as { inject_id?: unknown }).inject_id))).length;
  const phaseOf = (e: Ev, p: CardBody) => requestPhase(e.occurred_at ? Date.parse(e.occurred_at) : now, Number(p.deadline_s) || 240, now);
  const expiredCount = cards.filter(c => { const p = c.payload as unknown as CardBody; return !answered.has(p.inject_id) && phaseOf(c, p) === "closed"; }).length;
  const loadFb = useCallback(async () => {
    try {
      const r = await fetch(`/api/team/sessions/${sessionId}/manager`, { cache: "no-store" });
      if (r.ok) setFb(await r.json());
    } catch { /* next change retries */ }
  }, [sessionId]);
  useEffect(() => { void loadFb(); }, [loadFb, decidedCount, expiredCount, cards.length]);
  const fbOf = (id: string) => fb?.cards.find(c => c.inject_id === id);

  // Open and late cards stay on the desk (with whatever was typed); only a closed one moves down.
  const open = cards.map(c => ({ e: c, p: c.payload as unknown as CardBody })).filter(({ e, p }) => !answered.has(p.inject_id) && phaseOf(e, p) !== "closed");
  const past = cards.map(c => ({ e: c, p: c.payload as unknown as CardBody })).filter(({ p }) => !open.some(o => o.p.inject_id === p.inject_id)).reverse();

  return (
    <div data-command-desk className="scroll-mt-24">
    <Card className="border-neon-purple/40">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Gavel className="h-4 w-4 text-neon-purple" aria-hidden /> Command desk</h3>
      <div data-tour="desk-incident"><IncidentControl declared={!!declared} severity={severity} act={act} /></div>
      {fb && cards.length > 0 && <div data-tour="desk-impact"><IndicatorStrip ind={fb.indicators} /></div>}
      <div className="mt-3 space-y-2">
        {open.length === 0 && past.length === 0 && (
          <p className="text-[11px] leading-relaxed text-slate-400">No decisions waiting. Requests land here when the incident calls for them, each with a deadline.</p>
        )}
        {open.map(({ e, p }) => <OpenCard key={p.inject_id} e={e} p={p} now={now} act={act} onDone={loadFb} onOpenEscalations={onOpenEscalations} />)}
        {past.map(({ p }) => <PastCard key={p.inject_id} p={p} answer={answered.get(p.inject_id)} fb={fbOf(p.inject_id)} />)}
      </div>
    </Card>
    </div>
  );
}

function IncidentControl({ declared, severity, act }: { declared: boolean; severity: number | null; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [sev, setSev] = useState<number | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [changing, setChanging] = useState(false);
  async function declare() { if (sev == null) return; setBusy(true); await act("incident.declared", { severity: sev }); setBusy(false); }
  async function change() {
    if (!reason.trim() || sev == null || sev === severity) return;
    setBusy(true); const ok = await act("incident.severity_changed", { severity: sev, reason: reason.trim() }); setBusy(false);
    if (ok) { setChanging(false); setReason(""); }
  }
  const pick = <ChoiceGroup legend="Severity" options={SEVERITY.map(s => ({ value: s.v, label: s.label, hint: s.hint }))} value={sev} onChange={setSev} />;
  if (!declared) return (
    <div className="mt-2 space-y-1.5 rounded-lg border border-border bg-bg px-2.5 py-2">
      <p className="text-[11px] text-slate-300">Not declared. Declare when the first real escalation lands; you can change the severity later.</p>
      {pick}
      <p className="text-[11px] text-slate-400">{sev == null ? "Pick the severity that matches the impact." : SEVERITY.find(s => s.v === sev)?.hint}</p>
      <Button variant="primary" size="sm" disabled={busy || sev == null} onClick={declare}><Megaphone className="mr-1 h-3.5 w-3.5" aria-hidden /> Declare incident</Button>
    </div>
  );
  return (
    <div className="mt-2 rounded-lg border border-border bg-bg px-2.5 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded px-2 py-0.5 font-mono text-xs font-bold ${severity === 1 ? "bg-severity-critical/20 text-severity-critical" : severity === 2 ? "bg-severity-high/20 text-severity-high" : "bg-neon-amber/15 text-neon-amber"}`}>Sev-{severity}</span>
        <span className="text-[11px] text-slate-400">incident declared</span>
        {!changing && <button type="button" onClick={() => { setSev(severity ?? 2); setChanging(true); }} className="ml-auto text-[11px] text-cyber-300 underline">Change severity</button>}
      </div>
      {changing && (
        <div className="mt-2 space-y-1.5">
          {pick}
          <label className="block text-[11px] text-slate-300">Why (what changed in the picture)?
            <input value={reason} maxLength={300} onChange={e => setReason(e.target.value)} placeholder="e.g. exfiltration confirmed from the file server" className="mt-1 w-full rounded border border-border bg-bg-elevated px-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60" />
          </label>
          <div className="flex gap-1.5">
            <Button variant="outline" size="sm" disabled={busy || !reason.trim() || sev == null || sev === severity} onClick={change}>{sev == null ? "Pick a severity" : `Set Sev-${sev}`}</Button>
            <Button variant="ghost" size="sm" onClick={() => setChanging(false)}>Cancel</Button>
          </div>
        </div>
      )}
    </div>
  );
}

function IndicatorStrip({ ind }: { ind: Indicators }) {
  return (
    <div className="mt-2 grid grid-cols-[repeat(auto-fit,minmax(10.5rem,1fr))] gap-x-3 gap-y-1" aria-label="Impact indicators">
      {(Object.keys(IND_LABEL) as (keyof Indicators)[]).map(k => (
        <div key={k} className="flex items-center justify-between gap-1.5 text-[10px]">
          <span className="min-w-0 truncate text-slate-400">{IND_LABEL[k]}</span>
          <span className="flex gap-0.5" aria-label={`${ind[k]} of 5`}>
            {[0, 1, 2, 3, 4].map(i => <span key={i} className={`h-1.5 w-3 rounded-sm ${i < ind[k] ? (ind[k] <= 1 ? "bg-severity-critical" : ind[k] <= 2 ? "bg-neon-amber" : "bg-neon-green") : "bg-slate-700"}`} />)}
          </span>
        </div>
      ))}
    </div>
  );
}

function OpenCard({ e, p, now, act, onDone, onOpenEscalations }: { e: Ev; p: CardBody; now: number; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; onDone: () => void; onOpenEscalations?: () => void }) {
  const [option, setOption] = useState<string | null>(null);
  // No default: a pre-selected "medium" turned the calibration table into noise.
  const [confidence, setConfidence] = useState<"low" | "medium" | "high" | null>(null);
  const [rationale, setRationale] = useState("");
  const [busy, setBusy] = useState(false);
  const deadline = (e.occurred_at ? Date.parse(e.occurred_at) : now) + (Number(p.deadline_s) || 240) * 1000;
  const late = now > deadline;
  const left = late ? Math.max(0, Math.round((deadline + LATE_GRACE_S * 1000 - now) / 1000)) : Math.max(0, Math.round((deadline - now) / 1000));
  const Icon = channelIcon(p.channel);
  async function submit() {
    if (!option || !confidence) return;
    setBusy(true);
    const ok = await act("decision.answered", { inject_id: p.inject_id, option, confidence, rationale: rationale.trim().slice(0, 400) });
    setBusy(false);
    if (ok) onDone();
  }
  return (
    <div className={`rounded-lg border p-2.5 ${late ? "border-neon-amber/60 bg-neon-amber/[0.06]" : "border-neon-purple/50 bg-neon-purple/[0.06]"}`}>
      <div className="flex items-center gap-2 text-[11px]">
        <Icon className="h-3.5 w-3.5 text-neon-purple" aria-hidden />
        <span className="font-semibold text-white"><bdi>{asStr(p.from?.name)}</bdi></span>
        <span className="text-slate-400">{asStr(p.from?.role)} · {p.audience === "internal" ? "your team" : "stakeholder"}</span>
        <span className={`ml-auto flex items-center gap-1 font-mono ${late || left <= 30 ? "text-severity-critical" : "text-neon-amber"}`} aria-live="off"><Clock className="h-3 w-3" aria-hidden />{late && <span className="font-sans font-semibold">Late · </span>}{Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}</span>
      </div>
      {late && <p className="mt-1 text-[11px] text-neon-amber">The deadline passed. You can still decide in the next {Math.ceil(LATE_GRACE_S / 60)} minutes; it will count as late.</p>}
      <p className="mt-1.5 text-sm leading-relaxed text-slate-100"><bdi>{asStr(p.text)}</bdi></p>
      <fieldset className="mt-2 space-y-1">
        <legend className="sr-only">Your decision</legend>
        {(p.options ?? []).map(o => (
          <label key={o.id} className={`flex cursor-pointer items-start gap-2 rounded border px-2 py-1.5 text-xs transition ${option === o.id ? "border-neon-purple/60 bg-neon-purple/10 text-white" : "border-border bg-bg text-slate-300 hover:border-slate-500"}`}>
            <input type="radio" name={`card-${p.inject_id}`} value={o.id} checked={option === o.id} onChange={() => setOption(o.id)} className="mt-0.5" />
            <span>{o.label}</span>
          </label>
        ))}
      </fieldset>
      {p.about?.target && (
        <p className="mt-2 flex flex-wrap items-center gap-1.5 rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-300">
          This is about the containment request for <bdi className="font-mono text-slate-100">{p.about.target}</bdi>. Decide here, then approve or deny the request itself.
          {onOpenEscalations && <button type="button" onClick={onOpenEscalations} className="text-cyber-300 underline-offset-2 hover:underline">Open the request</button>}
        </p>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <span className="text-[11px] text-slate-300">How sure are you?</span>
        <ChoiceGroup legend="How sure are you?" size="xs" tone="cyan" value={confidence} onChange={setConfidence}
          options={[{ value: "low", label: "Low" }, { value: "medium", label: "Medium" }, { value: "high", label: "High" }]} />
      </div>
      <label className="mt-2 block text-[11px] text-slate-300">Why this call? <span className="text-slate-400">(optional, goes into your decision log)</span>
        <input value={rationale} maxLength={400} onChange={ev => setRationale(ev.target.value)} className="mt-1 w-full rounded border border-border bg-bg px-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/60 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/60" />
      </label>
      <div className="mt-2 flex items-center gap-2">
        <Button variant="primary" size="sm" disabled={busy || !option || !confidence} onClick={submit}>Decide</Button>
        {(!option || !confidence) && <span className="text-[11px] text-slate-400">{!option ? "Choose an option" : "Say how sure you are"} to decide.</span>}
      </div>
    </div>
  );
}

function PastCard({ p, answer, fb }: { p: CardBody; answer?: Ev; fb?: Feedback }) {
  const chosen = answer ? asStr((answer.payload as { option?: unknown }).option) : null;
  const label = (id?: string | null) => p.options?.find(o => o.id === id)?.label ?? "";
  const rank = fb?.rank ?? null;
  return (
    <details className="rounded-lg border border-border bg-bg px-2.5 py-1.5 text-xs" open={!!fb && fb.state !== "open" && !!rank && rank !== "great"}>
      <summary className="flex cursor-pointer items-center gap-2">
        <span className="font-semibold text-slate-200"><bdi>{asStr(p.from?.name)}</bdi></span>
        <span className="min-w-0 flex-1 truncate text-slate-400"><bdi>{asStr(p.text)}</bdi></span>
        {!answer ? <span className="rounded border border-severity-critical/40 px-1.5 text-[10px] text-severity-critical">no decision</span>
          : rank ? <span className={`rounded border px-1.5 text-[10px] ${RANK_STYLE[rank]}`}>{RANK_LABEL[rank]}</span>
            : <span className="text-[10px] text-slate-500">decided</span>}
      </summary>
      <div className="mt-1.5 space-y-1 border-t border-border/60 pt-1.5">
        {chosen ? <p className="text-slate-300">You chose: <b className="text-slate-100">{label(chosen)}</b>{fb?.notes?.[chosen] && <span className="text-slate-400"> {fb.notes[chosen]}</span>}</p>
          : <p className="text-severity-critical">No decision was made in time.</p>}
        {fb?.best && fb.best !== chosen && <p className="text-slate-300">Best: <b className="text-neon-green">{label(fb.best)}</b>{fb.notes?.[fb.best] && <span className="text-slate-400"> {fb.notes[fb.best]}</span>}</p>}
        {fb?.objective && <p className="text-[10px] text-slate-500">What this tests: {fb.objective}</p>}
        {fb?.delta && fmtDelta(fb.delta) && <p className="text-[10px] text-slate-400">Impact: {fmtDelta(fb.delta)}</p>}
      </div>
    </details>
  );
}

/** Decision cards still waiting for the manager (open or late), for the "Needs you" cluster. */
export function openDecisionCards(events: Ev[], now: number): number {
  const answered = new Set(events.filter(e => e.type === "decision.answered").map(e => asStr((e.payload as { inject_id?: unknown }).inject_id)));
  return events.filter(e => e.type === "staff.inject" && asStr((e.payload as { kind?: unknown }).kind) === "decision"
    && !answered.has(asStr((e.payload as { inject_id?: unknown }).inject_id))
    && requestPhase(e.occurred_at ? Date.parse(e.occurred_at) : now, Number((e.payload as { deadline_s?: unknown }).deadline_s) || 240, now) !== "closed").length;
}
