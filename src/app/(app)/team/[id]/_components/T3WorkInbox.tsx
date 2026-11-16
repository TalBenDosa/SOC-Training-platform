"use client";
import { useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Flag, MessagesSquare, RotateCcw, Check, HelpCircle } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { closedCases, consultsOf, shiftLeadOf, CONSULT_LABEL, type ConsultAnswer } from "@/lib/team/t3Work";

/**
 * Tier-3 own work (T3 interface spec, stage C), in the Tier-3 inbox: the open lead from the
 * previous shift, Tier-2's consults, and a second look at alerts the team closed as benign.
 */
export function T3WorkInbox({ events, feed, nameOf, act, onOpenCase }: {
  events: Ev[]; feed: Ev[]; nameOf: (u: string | null) => string;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>;
  /** Show the Case tab (after the lead is opened). */
  onOpenCase: () => void;
}) {
  const lead = useMemo(() => shiftLeadOf(events), [events]);
  const consults = useMemo(() => consultsOf(events).filter(c => !c.answer), [events]);
  const closed = useMemo(() => closedCases(events, feed).slice(0, 3), [events, feed]);
  const [busy, setBusy] = useState<string | null>(null);
  const [reason, setReason] = useState<Record<string, string>>({});
  const [err, setErr] = useState<Record<string, string>>({});
  const field = "w-full rounded border border-border bg-bg-elevated px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none";

  if ((!lead || lead.resolved) && !consults.length && !closed.length) return null;

  async function openLead() {
    if (!lead) return;
    setBusy("lead");
    const ok = await act("t3.scope.entity", { entity: lead.host, entity_kind: "host", state: "suspected", reason: "Open lead from the previous shift" });
    setBusy(null);
    if (ok) onOpenCase();
  }
  async function answer(seq: number, value: ConsultAnswer) {
    const k = `c${seq}`; const r = (reason[k] ?? "").trim();
    if (r.length < 10) { setErr(e => ({ ...e, [k]: "Give Tier-2 your reason (at least 10 characters)." })); return; }
    setBusy(k);
    await act("consult.answered", { consult_seq: seq, answer: value, reason: r.slice(0, 400) });
    setBusy(null);
  }
  async function review(eventId: string, decision: "agree" | "reopen") {
    const k = `r${eventId}`; const r = (reason[k] ?? "").trim();
    if (decision === "reopen" && r.length < 10) { setErr(e => ({ ...e, [k]: "Say what the closer missed (at least 10 characters)." })); return; }
    setBusy(k);
    await act("review.verdict", { event_id: eventId, decision, reason: r.slice(0, 400) || undefined });
    setBusy(null);
  }

  return (
    <Card className="border-cyber-500/30">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><MessagesSquare className="h-4 w-4 text-cyber-300" aria-hidden /> Your inbox: your own work</h3>
      <div className="mt-2 space-y-3">
        {lead && !lead.resolved && (
          <div className="rounded-lg border border-neon-amber/40 bg-neon-amber/5 px-2.5 py-2 text-xs">
            <p className="flex items-center gap-1.5 font-semibold text-neon-amber"><Flag className="h-3.5 w-3.5" aria-hidden /> Open lead from the previous shift</p>
            <p className="mt-1 text-slate-200">{lead.text}</p>
            {lead.opened
              ? <p className="mt-1 text-[11px] text-slate-300">In your scope register as a suspect: collect on <span className="font-mono">{lead.host}</span>, then confirm or clear it with evidence.</p>
              : <Button variant="primary" size="sm" className="mt-2" disabled={busy === "lead"} onClick={() => void openLead()}>Open the lead</Button>}
          </div>
        )}

        {consults.map(c => {
          const k = `c${c.seq}`;
          return (
            <div key={c.seq} className="rounded-lg border border-border bg-bg px-2.5 py-2 text-xs">
              <p className="flex items-center gap-1.5 font-semibold text-cyber-200"><HelpCircle className="h-3.5 w-3.5" aria-hidden /> Consult from {nameOf(c.by)}</p>
              <p className="mt-1 text-slate-200">{c.question}{c.host && <> <span className="text-slate-400">on</span> <span className="font-mono">{c.host}</span></>}</p>
              <label className="mt-1.5 block text-[11px] text-slate-400" htmlFor={`consult-${c.seq}`}>Your reason</label>
              <input id={`consult-${c.seq}`} value={reason[k] ?? ""} maxLength={400} onChange={e => setReason(m => ({ ...m, [k]: e.target.value }))} placeholder="e.g. the parent is the signed updater and the hash is known good" className={field} />
              {err[k] && <p role="alert" className="mt-1 text-[11px] text-neon-amber">{err[k]}</p>}
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {(["infected", "not_infected", "need_evidence"] as ConsultAnswer[]).map(v => (
                  <Button key={v} size="sm" variant={v === "need_evidence" ? "ghost" : "outline"} disabled={busy === k} onClick={() => void answer(c.seq, v)}>{CONSULT_LABEL[v]}</Button>
                ))}
              </div>
            </div>
          );
        })}

        {closed.length > 0 && (
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Closed alerts: a second look</p>
            <p className="text-[11px] text-slate-400">The team closed these as benign. Agree, or reopen one that was a miss. Who closed it is not shown.</p>
            <ul className="mt-1.5 space-y-1.5">
              {closed.map(c => {
                const k = `r${c.eventId}`;
                return (
                  <li key={c.eventId} className="rounded-lg border border-border bg-bg px-2.5 py-2 text-xs">
                    <p className="text-slate-200"><bdi>{c.summary}</bdi>{c.host && <> <span className="text-slate-400">on</span> <span className="font-mono">{c.host}</span></>} <span className="text-slate-400">closed as {c.verdict.replace("_", " ")}</span></p>
                    <input aria-label="Reason" value={reason[k] ?? ""} maxLength={400} onChange={e => setReason(m => ({ ...m, [k]: e.target.value }))} placeholder="Reason (required to reopen)" className={`${field} mt-1.5`} />
                    {err[k] && <p role="alert" className="mt-1 text-[11px] text-neon-amber">{err[k]}</p>}
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      <Button size="sm" variant="outline" disabled={busy === k} onClick={() => void review(c.eventId, "agree")}><Check className="h-3.5 w-3.5" aria-hidden /> Agree</Button>
                      <Button size="sm" variant="secondary" disabled={busy === k} onClick={() => void review(c.eventId, "reopen")}><RotateCcw className="h-3.5 w-3.5" aria-hidden /> Reopen</Button>
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </div>
    </Card>
  );
}

/**
 * Tier-2: ask Tier-3 for a second opinion on one of your cases, without handing it over.
 * Answers come back here.
 */
export function ConsultAsk({ events, feed, meId, nameOf, act }: {
  events: Ev[]; feed: Ev[]; meId: string; nameOf: (u: string | null) => string;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>;
}) {
  const rowOf = useMemo(() => new Map(feed.map(f => [String((f.payload as { id?: unknown }).id ?? ""), f.payload as Record<string, unknown>])), [feed]);
  // My cases: escalations I acknowledged, newest first.
  const cases = useMemo(() => {
    const seen = new Set<string>(); const out: { eventId: string; label: string; host: string }[] = [];
    for (const e of [...events].reverse()) {
      if (e.type !== "escalation.acknowledged" || e.actor_id !== meId) continue;
      const eid = String((e.payload as { event_id?: unknown }).event_id ?? "");
      if (!eid || seen.has(eid)) continue; seen.add(eid);
      const r = rowOf.get(eid) ?? {};
      out.push({ eventId: eid, label: String(r.description ?? r.event_type ?? eid).slice(0, 80), host: String(r.hostname ?? "") });
    }
    return out.slice(0, 12);
  }, [events, meId, rowOf]);
  const mine = useMemo(() => consultsOf(events).filter(c => c.by === meId), [events, meId]);
  const [eid, setEid] = useState("");
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const pick = cases.find(c => c.eventId === eid) ?? cases[0];

  async function ask() {
    if (!pick) return;
    if (q.trim().length < 10) { setErr("Say what you want Tier-3 to judge (at least 10 characters)."); return; }
    setErr(null); setBusy(true);
    const ok = await act("consult.asked", { event_id: pick.eventId, host: pick.host || undefined, question: q.trim().slice(0, 400) });
    setBusy(false);
    if (ok) setQ("");
  }

  if (!cases.length && !mine.length) return null;
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><HelpCircle className="h-4 w-4 text-cyber-300" aria-hidden /> Ask Tier-3</h3>
      <p className="mt-1 text-[11px] text-slate-400">Unsure whether a host is infected? Ask Tier-3 for a second opinion. The case stays yours.</p>
      {cases.length > 0 && (
        <div className="mt-2 space-y-1.5">
          <label className="block text-[11px] text-slate-400" htmlFor="consult-case">Case</label>
          <select id="consult-case" value={pick?.eventId ?? ""} onChange={e => setEid(e.target.value)} className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-slate-200 focus:outline-none">
            {cases.map(c => <option key={c.eventId} value={c.eventId}>{c.label}{c.host ? ` (${c.host})` : ""}</option>)}
          </select>
          <label className="block text-[11px] text-slate-400" htmlFor="consult-q">Your question</label>
          <input id="consult-q" value={q} onChange={e => setQ(e.target.value)} maxLength={400} placeholder="e.g. Is WS-047 infected, or is this the patch agent?" className="w-full rounded border border-border bg-bg px-2 py-1 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none" />
          {err && <p role="alert" className="text-[11px] text-neon-amber">{err}</p>}
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void ask()}>Ask Tier-3</Button>
        </div>
      )}
      {mine.length > 0 && (
        <ul className="mt-3 space-y-1 text-[11px]">
          {mine.slice().reverse().map(c => (
            <li key={c.seq} className="rounded border border-border bg-bg px-2 py-1">
              <span className="text-slate-300">{c.question}</span>{" "}
              {c.answer
                ? <span className={c.answer.value === "infected" ? "text-severity-high" : c.answer.value === "not_infected" ? "text-neon-green" : "text-neon-amber"}>{nameOf(c.answer.by)}: {CONSULT_LABEL[c.answer.value]}. {c.answer.reason}</span>
                : <span className="text-slate-500">waiting for Tier-3</span>}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
