"use client";
import { useCallback, useEffect, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Timer, FastForward } from "lucide-react";
import type { PendingAttack } from "@/lib/team/schedule";

// ── Instructor: the attacks still to come (staff only) ─────────────────────────
// 2026-10-18 review: in two of four exercises the primary incident was still due when the
// session ended and nothing said so. Shows each attack that hasn't reached the feed with a
// countdown on the shift clock, and brings the next one forward on request.
const mmss = (ms: number) => { const s = Math.max(0, Math.round(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };
const KIND_LABEL: Record<PendingAttack["kind"], string> = { planned: "planned", standalone: "standalone", bonus: "bonus (after every planned catch)" };
const label = (inc: string) => inc.replace(/^story:/, "").replace(/^inc:/, "").replace(/^pool:/, "").replace(/^solo:/, "").replace(/[_:-]+/g, " ").trim();

export function AttackSchedule({ sessionId, onError }: { sessionId: string; onError?: (m: string) => void }) {
  const [data, setData] = useState<{ elapsedMs: number; pending: PendingAttack[]; status: string; at: number } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  const refresh = useCallback(async () => {
    const res = await fetch(`/api/team/sessions/${sessionId}/schedule`).catch(() => null);
    if (!res || !res.ok) return;
    const d = await res.json().catch(() => null);
    if (d) setData({ ...d, at: Date.now() });
  }, [sessionId]);
  useEffect(() => { refresh(); const t = setInterval(refresh, 15000); return () => clearInterval(t); }, [refresh]);
  useEffect(() => { const t = setInterval(() => setTick(x => x + 1), 1000); return () => clearInterval(t); }, []);

  async function release(incident?: string) {
    setBusy(incident ?? "next");
    const res = await fetch(`/api/team/sessions/${sessionId}/schedule`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(incident ? { incident } : {}) }).catch(() => null);
    setBusy(null);
    if (!res || !res.ok) { onError?.((await res?.json().catch(() => ({})))?.error ?? "Couldn't release the attack."); return; }
    refresh();
  }

  if (!data) return null;
  void tick;
  const now = data.status === "paused" ? data.elapsedMs : data.elapsedMs + (Date.now() - data.at);
  const planned = data.pending.filter(p => p.kind !== "bonus");
  const next = planned[0];
  return (
    <Card className="border-cyber-500/30">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Timer className="h-4 w-4 text-cyber-300" aria-hidden="true" /> Attacks still to come</h3>
        <span className="font-mono text-[11px] text-slate-400">shift clock {mmss(now)}</span>
        <span className="ml-auto rounded border border-neon-amber/40 px-1 py-0.5 text-[9px] font-bold uppercase text-neon-amber">staff only</span>
      </div>
      {data.pending.length === 0 ? <p className="mt-2 text-xs text-slate-400">Every attack has reached the feed.</p> : (
        <>
          {next && next.firstDueMs != null && (
            <p className="mt-2 text-xs text-slate-300">Next: <b className="text-white">{label(next.incident)}</b> in <b className="font-mono text-cyber-300">{mmss(next.firstDueMs - now)}</b></p>
          )}
          <ul className="mt-2 space-y-1">
            {data.pending.map(p => (
              <li key={p.incident} className="flex items-center gap-2 rounded border border-border bg-bg px-2 py-1 text-[11px]">
                <span className="min-w-0 flex-1 truncate text-slate-200" title={p.incident}>{label(p.incident)}</span>
                <span className="shrink-0 text-slate-500">{KIND_LABEL[p.kind]}</span>
                <span className="shrink-0 font-mono text-slate-400">{p.firstDueMs != null ? `in ${mmss(p.firstDueMs - now)}` : "held"}</span>
                <Button size="sm" variant="outline" disabled={busy !== null} onClick={() => release(p.incident)} aria-label={`Release ${label(p.incident)} now`}>
                  <FastForward className="mr-1 h-3 w-3" aria-hidden="true" />{busy === p.incident ? "…" : "Now"}
                </Button>
              </li>
            ))}
          </ul>
          <p className="mt-1.5 text-[10px] text-slate-500">&quot;Now&quot; starts that attack in about five seconds, at its own pace.</p>
        </>
      )}
    </Card>
  );
}
