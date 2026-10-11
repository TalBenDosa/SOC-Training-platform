"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { MessagesSquare, Clock, Check, X } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { useServerNow } from "@/lib/team/clock";
import { requestPhase, LATE_GRACE_S } from "@/lib/team/manager/timing";

/**
 * The stakeholder window (SOC Manager): from the moment the incident is declared, the CISO, the
 * CEO's office, Legal, the head of an affected department and Communications ask what they
 * really ask in an incident ("where are we?", "how long?", "is data affected?"). Each question
 * is raised by the server only from what is happening in the session. The manager answers in
 * free text; after answering, the checks on the reply and a model answer appear.
 */

interface QFeedback { inject_id: string; state: "open" | "answered" | "expired"; late?: boolean; checks?: { id: string; label: string; ok: boolean }[]; score?: number; model?: string }

export function StakeholderWindow({ sessionId, events, act, declared }: { sessionId: string; events: Ev[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; declared: boolean }) {
  const now = useServerNow(1_000);
  const asked = useMemo(() => events.filter(e => e.type === "stakeholder.asked"), [events]);
  const replies = useMemo(() => new Map(events.filter(e => e.type === "stakeholder.replied").map(e => [asStr((e.payload as { inject_id?: unknown }).inject_id), e])), [events]);
  const [fb, setFb] = useState<QFeedback[]>([]);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const deadlineOf = (e: Ev) => (e.occurred_at ? Date.parse(e.occurred_at) : now) + (Number((e.payload as { deadline_s?: unknown }).deadline_s) || 240) * 1000;
  const phaseOf = (e: Ev) => requestPhase(e.occurred_at ? Date.parse(e.occurred_at) : now, Number((e.payload as { deadline_s?: unknown }).deadline_s) || 240, now);
  const expiredCount = asked.filter(e => !replies.has(asStr((e.payload as { inject_id?: unknown }).inject_id)) && phaseOf(e) === "closed").length;

  const load = useCallback(async () => {
    try {
      const r = await fetch(`/api/team/sessions/${sessionId}/manager`, { cache: "no-store" });
      if (r.ok) setFb(((await r.json()).questions ?? []) as QFeedback[]);
    } catch { /* retried on the next change */ }
  }, [sessionId]);
  useEffect(() => { if (asked.length) void load(); }, [load, asked.length, replies.size, expiredCount]);

  if (!declared) return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><MessagesSquare className="h-4 w-4 text-neon-purple" aria-hidden /> Stakeholders</h3>
      <p className="mt-1 text-[11px] text-slate-400">Opens when you declare the incident. From then on the CISO, executives, Legal and the business ask you for status here.</p>
    </Card>
  );

  const open = asked.filter(e => !replies.has(asStr((e.payload as { inject_id?: unknown }).inject_id)) && phaseOf(e) !== "closed").length;
  async function send(id: string) {
    const text = (draft[id] ?? "").trim();
    if (!text) return;
    setBusy(id);
    const ok = await act("stakeholder.replied", { inject_id: id, text: text.slice(0, 1200) });
    setBusy(null);
    if (ok) { setDraft(d => ({ ...d, [id]: "" })); void load(); }
  }

  return (
    <div id="team-stakeholders" className="scroll-mt-24">
      <Card className="border-neon-purple/30">
        <div className="flex items-center gap-2">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white"><MessagesSquare className="h-4 w-4 text-neon-purple" aria-hidden /> Stakeholders</h3>
          {open > 0 && <span className="rounded-full bg-neon-purple/20 px-2 font-mono text-[10px] text-neon-purple">{open} waiting</span>}
        </div>
        {asked.length === 0 && <p className="mt-1 text-[11px] text-slate-400">Quiet for now. Questions arrive as the incident develops: answer with what is confirmed, what is not, and when the next update comes.</p>}
        <div className="mt-2 space-y-2">
          {asked.map(e => {
            const p = e.payload as { inject_id?: string; from?: { name?: string; role?: string }; text?: string };
            const id = asStr(p.inject_id);
            const r = replies.get(id);
            const phase = phaseOf(e);
            const late = phase === "late";
            const left = Math.max(0, Math.round(((late ? deadlineOf(e) + LATE_GRACE_S * 1000 : deadlineOf(e)) - now) / 1000));
            const f = fb.find(x => x.inject_id === id);
            return (
              <div key={e.seq} className="space-y-1.5">
                <div className="rounded-lg rounded-tl-none border border-border bg-bg px-2.5 py-2">
                  <div className="flex items-center gap-2 text-[10px]">
                    <b className="text-slate-200"><bdi>{asStr(p.from?.name)}</bdi></b><span className="text-slate-500">{asStr(p.from?.role)}</span>
                    {!r && phase !== "closed" && <span className={`ml-auto flex items-center gap-1 font-mono ${late || left <= 30 ? "text-severity-critical" : "text-neon-amber"}`}><Clock className="h-3 w-3" aria-hidden />{late && <span className="font-sans font-semibold">Late · </span>}{Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}</span>}
                    {!r && phase === "closed" && <span className="ml-auto text-severity-critical">no answer</span>}
                  </div>
                  <p className="mt-0.5 text-xs leading-relaxed text-slate-100"><bdi>{asStr(p.text)}</bdi></p>
                </div>
                {r ? (
                  <div className="ml-6 rounded-lg rounded-tr-none border border-neon-purple/30 bg-neon-purple/[0.07] px-2.5 py-1.5 text-xs text-slate-100">
                    <bdi>{asStr((r.payload as { text?: unknown }).text)}</bdi>
                    {f?.state === "answered" && f.checks && (
                      <div className="mt-1.5 space-y-0.5 border-t border-neon-purple/20 pt-1.5">
                        {f.late && <p className="text-[10px] text-neon-amber">Answered after the deadline.</p>}
                        {f.checks.map(c => (
                          <p key={c.id} className={`flex items-center gap-1 text-[10px] ${c.ok ? "text-neon-green" : "text-neon-amber"}`}>{c.ok ? <Check className="h-3 w-3" aria-hidden /> : <X className="h-3 w-3" aria-hidden />}{c.label}</p>
                        ))}
                        {f.model && f.checks.some(c => !c.ok) && <p className="text-[10px] text-slate-400">A strong answer: {f.model}</p>}
                      </div>
                    )}
                  </div>
                ) : phase !== "closed" ? (
                  <div className="ml-6 space-y-1">
                    {late && <p className="text-[11px] text-neon-amber">Past the deadline: you can still answer for {Math.ceil(LATE_GRACE_S / 60)} more minutes, marked late.</p>}
                    <textarea aria-label={`Answer ${asStr(p.from?.name)}`} value={draft[id] ?? ""} rows={4} maxLength={1200}
                      onChange={ev => setDraft(d => ({ ...d, [id]: ev.target.value }))}
                      placeholder="What is confirmed, what is not yet known, what you are doing, and when the next update comes."
                      className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-neon-purple/50 focus:outline-none" />
                    <Button variant="primary" size="sm" disabled={busy === id || !(draft[id] ?? "").trim()} onClick={() => send(id)}>Reply</Button>
                  </div>
                ) : f?.model ? <p className="ml-6 text-[11px] text-slate-400">A strong answer would have been: {f.model}</p> : null}
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}

/** Questions still waiting for the manager (for the menu badge). */
export function openStakeholderQuestions(events: Ev[], now: number): number {
  const replied = new Set(events.filter(e => e.type === "stakeholder.replied").map(e => asStr((e.payload as { inject_id?: unknown }).inject_id)));
  return events.filter(e => e.type === "stakeholder.asked" && !replied.has(asStr((e.payload as { inject_id?: unknown }).inject_id))
    && requestPhase(e.occurred_at ? Date.parse(e.occurred_at) : now, Number((e.payload as { deadline_s?: unknown }).deadline_s) || 240, now) !== "closed").length;
}
