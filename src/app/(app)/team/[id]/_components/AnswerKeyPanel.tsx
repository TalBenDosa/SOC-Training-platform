"use client";
import { useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { KeyRound, ChevronDown } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { escalationStates } from "@/lib/team/projections";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";

// ── Instructor: live "answer key vs team" (staff only) ────────────────────────
// Instructor playtest: the only way to see which fired logs were attacks — and
// whether the team caught them — was a hand-written SQL query. The key lives in the
// staff-only `session_injects.expected_action` (RLS: session staff can SELECT it,
// same read InjectFeed uses for the real inject kind); it's joined here to the live
// event log by `fired_seq`. Never rendered for non-staff (the caller gates on is_staff
// and RLS returns nothing to anyone else anyway).
interface KeyRow { id: string; channel: "feed" | "inject"; status: string; fired_seq: number | null; due_offset_ms: number | null; expected_action: Record<string, unknown> | null; body?: Record<string, unknown> | null }
const ATTACK = new Set(["tp", "escalate"]);
const mmss = (ms: number | null) => { if (ms == null) return "—"; const s = Math.max(0, Math.round(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };

export function AnswerKeyPanel({ sessionId, events, nameOf }: { sessionId: string; events: Ev[]; nameOf: (u: string | null) => string }) {
  const [rows, setRows] = useState<KeyRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState(true);
  // Refetch when something new fires (feed log or inject) — debounced, so a burst is one read.
  const firedCount = useMemo(() => events.filter(e => e.type === "feed.event" || e.type === "staff.inject").length, [events]);
  useEffect(() => {
    const sb = getSupabaseBrowserClient();
    if (!sb) return;
    let cancelled = false;
    const t = setTimeout(async () => {
      const [feedQ, injQ] = await Promise.all([
        sb.from("session_injects").select("id, channel, status, fired_seq, due_offset_ms, expected_action").eq("session_id", sessionId).eq("channel", "feed"),
        sb.from("session_injects").select("id, channel, status, fired_seq, due_offset_ms, expected_action, body").eq("session_id", sessionId).eq("channel", "inject"),
      ]);
      if (cancelled) return;
      if (feedQ.error || injQ.error) { setErr("Couldn't read the answer key (staff only)."); return; }
      setErr(null);
      setRows([...(feedQ.data ?? []), ...(injQ.data ?? [])] as KeyRow[]);
    }, 1500);
    return () => { cancelled = true; clearTimeout(t); };
  }, [sessionId, firedCount]);

  const bySeq = useMemo(() => new Map(events.map(e => [e.seq, e])), [events]);
  const escStates = useMemo(() => escalationStates(events), [events]);
  // Per event id: who claimed it, the latest T1 verdict.
  const actions = useMemo(() => {
    const claim = new Map<string, string>(), verdict = new Map<string, string>();
    for (const e of events) {
      const eid = String((e.payload as { event_id?: unknown }).event_id ?? "");
      if (!eid) continue;
      if (e.type === "alert.claimed") claim.set(eid, e.actor_id ?? "");
      else if (e.type === "disposition.set") verdict.set(eid, asStr((e.payload as { verdict?: unknown }).verdict));
    }
    return { claim, verdict };
  }, [events]);

  const view = useMemo(() => {
    if (!rows) return null;
    type Step = { seq: number; eid: string; desc: string; expected: string; control: boolean; claimedBy?: string; verdict?: string; escalated: boolean; state: string; correct: boolean | null };
    const incidents = new Map<string, Step[]>();
    for (const r of rows) {
      if (r.channel !== "feed" || r.status !== "fired" || r.fired_seq == null) continue;
      const ea = r.expected_action ?? {};
      const expected = asStr(ea.expected_verdict) || "benign";
      const inc = asStr(ea.incident_id);
      if (!ATTACK.has(expected) && !inc) continue;                 // pure noise — not on the board
      const ev = bySeq.get(r.fired_seq); if (!ev) continue;
      const p = ev.payload as { id?: unknown; description?: unknown; event_type?: unknown };
      const eid = String(p.id ?? ev.seq);
      const st = escStates.get(eid);
      const v = actions.verdict.get(eid);
      const control = !ATTACK.has(expected);
      const correct = v ? (control ? v === "benign" || v === "false_positive" : v === "true_positive" || v === "suspicious") : null;
      const step: Step = { seq: ev.seq, eid, desc: asStr(p.description) || asStr(p.event_type) || "log", expected, control, claimedBy: actions.claim.get(eid), verdict: v, escalated: !!st && st.rounds > 0, state: st ? (st.resolved ? "resolved" : st.bounced ? "bounced" : st.acked ? "taken" : "open") : "", correct };
      const key = inc || `solo:${eid}`;
      incidents.set(key, [...(incidents.get(key) ?? []), step]);
    }
    const injects = rows.filter(r => r.channel === "inject").sort((a, b) => (a.due_offset_ms ?? 0) - (b.due_offset_ms ?? 0)).map(r => {
      const ea = r.expected_action ?? {};
      const kind = asStr(ea.kind) || asStr(r.body?.kind) || "announcement";
      const fired = r.status === "fired" && r.fired_seq != null ? r.fired_seq : null;
      const after = (types: string[]) => fired == null ? undefined : events.find(e => e.seq > fired && types.includes(e.type));
      let answer = "";
      if (fired != null) {
        if (kind === "ticket") { const t = events.find(e => e.type === "ticket.answered" && Number((e.payload as { ticket_seq?: unknown }).ticket_seq) === fired); answer = t ? `answered (${asStr((t.payload as { decision?: unknown }).decision) || "handled"}) by ${nameOf(t.actor_id)}` : "not answered"; }
        else if (kind === "mgmt_pressure") { const s = after(["sitrep.sent"]); answer = s ? `SITREP by ${nameOf(s.actor_id)}` : "no SITREP yet"; }
        else if (kind === "twist") { const s = after(["scope.set", "scope.confirmed", "escalation.requested"]); answer = s ? `re-scope / re-escalation seen (${s.type})` : "no re-scope yet"; }
        else if (kind === "false_lead") answer = `${events.filter(e => e.seq > fired && e.type === "escalation.requested").length} escalation(s) since — check none chase the decoy`;
        else answer = "FYI";
      }
      return { id: r.id, kind, status: r.status, due: r.due_offset_ms, text: asStr(r.body?.text), expected: asStr(ea.expected_response), answer, fired };
    });
    return { incidents: [...incidents.entries()], injects };
  }, [rows, bySeq, escStates, actions, events, nameOf]);

  return (
    <Card className="border-neon-amber/30">
      <button onClick={() => setOpen(o => !o)} className="flex w-full items-center gap-2 text-left">
        <ChevronDown className={`h-4 w-4 text-slate-400 transition-transform ${open ? "" : "-rotate-90"}`} />
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><KeyRound className="h-4 w-4 text-neon-amber" /> Answer key vs team</h3>
        <span className="ml-auto rounded border border-neon-amber/40 px-1 py-0.5 text-[9px] font-bold uppercase text-neon-amber">staff only</span>
      </button>
      {open && (
        err ? <p className="mt-2 text-xs text-severity-high">{err}</p>
        : !view ? <p className="mt-2 text-xs text-slate-500">Loading the key…</p>
        : <div className="mt-2 space-y-3">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Fired attack logs by incident ({view.incidents.length})</p>
            {view.incidents.length === 0 ? <p className="mt-1 text-[11px] text-slate-500">No attack activity has fired yet.</p> : (
              <div className="mt-1 max-h-[380px] space-y-2 overflow-y-auto">
                {view.incidents.map(([inc, steps]) => {
                  const attacks = steps.filter(s => !s.control);
                  const caught = attacks.some(s => s.escalated);
                  return (
                    <div key={inc} className="rounded-lg border border-border bg-bg px-2 py-1.5">
                      <div className="flex items-center gap-2 text-[11px]">
                        <span className="min-w-0 flex-1 truncate font-mono text-slate-300">{inc.startsWith("solo:") ? "standalone attack" : inc}</span>
                        <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${caught ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-severity-high/40 bg-severity-high/10 text-severity-high"}`}>{caught ? "escalated" : "not escalated"}</span>
                        <span className="shrink-0 font-mono text-[10px] text-slate-500">{attacks.filter(s => s.escalated).length}/{attacks.length} steps</span>
                      </div>
                      <div className="mt-1 space-y-0.5">
                        {steps.map(s => (
                          <div key={s.seq} className="flex items-center gap-1.5 text-[10px]">
                            <span className="shrink-0 font-mono text-slate-500">#{s.seq}</span>
                            <span className={`shrink-0 rounded px-1 font-mono uppercase ${s.control ? "bg-white/5 text-slate-400" : "bg-severity-high/15 text-severity-high"}`}>{s.control ? `control·${s.expected}` : s.expected}</span>
                            <span className="min-w-0 flex-1 truncate text-slate-300" title={s.desc}>{s.desc}</span>
                            {s.claimedBy && <span className="shrink-0 text-slate-500">🔒{nameOf(s.claimedBy)}</span>}
                            {s.verdict && <span className={`shrink-0 font-mono ${s.correct ? "text-neon-green" : "text-neon-amber"}`}>{s.verdict.replace("_", " ")}</span>}
                            {s.escalated ? <span className={`shrink-0 font-mono ${s.control ? "text-neon-amber" : "text-neon-green"}`}>↑{s.state}</span> : !s.control && !s.verdict && <span className="shrink-0 font-mono text-slate-600">untouched</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Injects ({view.injects.filter(i => i.fired != null).length}/{view.injects.length} fired)</p>
            <div className="mt-1 space-y-1">
              {view.injects.map(i => (
                <div key={i.id} className={`rounded border px-2 py-1 text-[10px] ${i.status === "pending" ? "border-border/50 text-slate-500" : "border-border bg-bg text-slate-300"}`}>
                  <p><span className="mr-1 font-mono uppercase text-neon-amber">{i.kind.replace("_", " ")}</span>{i.status === "pending" ? `due at ${mmss(i.due)} (shift clock)` : i.status === "fired" ? `fired #${i.fired}` : i.status} {i.answer && <span className="ml-1 text-cyber-300">· {i.answer}</span>}</p>
                  {i.text && <p className="mt-0.5 truncate text-slate-400" title={i.text}>{i.text}</p>}
                  {i.expected && <p className="mt-0.5 text-slate-500">expected: {i.expected}</p>}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}
