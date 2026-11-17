"use client";
import { useMemo, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ClipboardCheck } from "lucide-react";
import type { Ev } from "@/lib/team/types";
import { asStr, hostKey } from "@/lib/team/format";
import { buildRegister, scansOf } from "@/lib/team/t3Case";
import { closeoutOpen, closeoutsOf, detectionPreview, VECTOR_LABEL, type Vector } from "@/lib/team/t3Closeout";

/**
 * Tier-3 close-out (T3 interface spec, stage E): root cause, eradication and one detection, written
 * from what the Tier-3 already found. Every list is picked from the register, the findings and the
 * sweeps; only the notes are free text. Graded against the story after the session.
 */
export function T3CloseoutTab({ events, feed, nameOf, act }: {
  events: Ev[]; feed: Ev[]; nameOf: (u: string | null) => string;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>;
}) {
  const register = useMemo(() => buildRegister(events), [events]);
  const hosts = register.filter(r => r.kind === "host" && r.state === "confirmed");
  const accounts = register.filter(r => r.kind === "account" && r.state !== "cleared");
  const persistence = useMemo(() => events.filter(e => e.type === "forensic.finding" && (e.payload as { kind?: unknown }).kind === "persistence"), [events]);
  const indicators = useMemo(() => [...new Set(scansOf(events).filter(s => s.hosts.length).map(s => s.indicator))], [events]);
  const done = closeoutsOf(events);
  const last = done[done.length - 1] ?? null;
  const open = closeoutOpen(events);

  const [vector, setVector] = useState<Vector | "">("");
  const [first, setFirst] = useState("");
  const [remove, setRemove] = useState<Set<number>>(new Set());
  const [reset, setReset] = useState<Set<string>>(new Set());
  const [block, setBlock] = useState<Set<string>>(new Set());
  const [detection, setDetection] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const preview = useMemo(() => detectionPreview(feed, detection), [feed, detection]);

  const toggle = <T,>(set: Set<T>, v: T, put: (s: Set<T>) => void) => { const n = new Set(set); if (n.has(v)) n.delete(v); else n.add(v); put(n); };
  async function submit() {
    if (!vector) { setErr("Choose how the attacker got in (or Cannot determine)."); return; }
    if (!first && vector !== "cannot_determine") { setErr("Choose the first host, from your confirmed scope."); return; }
    if (detection.trim().length < 3) { setErr("Propose one detection: a search that would have caught this earlier."); return; }
    setErr(null); setBusy(true);
    await act("t3.closeout", { vector, first_host: first || undefined, remove: [...remove], reset: [...reset], block: [...block], detection: detection.trim().slice(0, 300), notes: notes.trim().slice(0, 1000) || undefined });
    setBusy(false);
  }
  const box = "rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none";

  return (
    <Card>
      <div data-tour="t3-closeout">
        <h2 className="flex items-center gap-2 text-sm font-bold text-white"><ClipboardCheck className="h-4 w-4 text-cyber-300" aria-hidden /> Close-out: root cause, eradication, detection</h2>
        <p className="mt-1 text-[11px] text-slate-400">Write down what the team needs to make sure the attacker cannot come back: how they got in, where it started, what to remove and reset, what to block, and one search that would have caught it earlier. &quot;Cannot determine&quot; is a right answer when the evidence is gone; a guess is not.</p>
        {!open && <p className="mt-2 rounded border border-border bg-bg-elevated/60 px-2 py-1.5 text-[11px] text-slate-300">Opens after containment starts or you sign a readiness verdict. Until then, keep scoping.</p>}
        {last && (
          <div className="mt-3 rounded-lg border border-neon-green/40 bg-neon-green/5 px-3 py-2 text-xs text-slate-200">
            <p className="font-semibold text-neon-green">Close-out sent by {nameOf(last.by)}</p>
            <p className="mt-1">Entry: {VECTOR_LABEL[last.vector]}{last.firstHost && <> · first host <span className="font-mono">{last.firstHost}</span></>}</p>
            <p>Remove {last.remove.length} item{last.remove.length === 1 ? "" : "s"} · reset {last.reset.length} account{last.reset.length === 1 ? "" : "s"} · block {last.block.length} indicator{last.block.length === 1 ? "" : "s"}</p>
            <p>Detection: <span className="font-mono">{last.detection}</span></p>
            <p className="mt-1 text-[11px] text-slate-400">You can send a corrected one; the latest counts.</p>
          </div>
        )}
        <fieldset disabled={!open} className="mt-3 space-y-3 border-0 p-0">
          <label className="block text-[11px] font-semibold text-slate-300">How did the attacker get in?
            <select value={vector} onChange={e => setVector(e.target.value as Vector)} className={`${box} mt-1 w-full text-xs`}>
              <option value="">Choose</option>
              {(Object.keys(VECTOR_LABEL) as Vector[]).map(v => <option key={v} value={v}>{VECTOR_LABEL[v]}</option>)}
            </select>
          </label>
          <label className="block text-[11px] font-semibold text-slate-300">First host (patient zero)
            <select value={first} onChange={e => setFirst(e.target.value)} className={`${box} mt-1 w-full font-mono text-xs`}>
              <option value="">{hosts.length ? "Choose from your confirmed scope" : "No confirmed host in the register yet"}</option>
              {hosts.map(h => <option key={h.key} value={h.entity}>{h.entity}</option>)}
            </select>
          </label>
          <fieldset className="border-0 p-0">
            <legend className="text-[11px] font-semibold text-slate-300">What to remove (your persistence findings)</legend>
            {persistence.length ? persistence.map(f => {
              const p = f.payload as Record<string, unknown>;
              return (
                <label key={f.seq} className="mt-1 flex items-start gap-2 text-xs text-slate-200">
                  <input type="checkbox" checked={remove.has(f.seq)} onChange={() => toggle(remove, f.seq, setRemove)} className="mt-0.5 h-3 w-3" />
                  <span><span className="font-mono">{asStr(p.host)}</span>: {asStr(p.summary).slice(0, 140)}</span>
                </label>
              );
            }) : <p className="mt-1 text-[11px] text-slate-400">No persistence finding yet. If you found none, leave it empty; if you did, publish it as a finding in the Evidence tab first.</p>}
          </fieldset>
          <fieldset className="border-0 p-0">
            <legend className="text-[11px] font-semibold text-slate-300">Accounts to reset (from your register)</legend>
            {accounts.length ? accounts.map(a => (
              <label key={a.key} className="mr-3 mt-1 inline-flex items-center gap-1.5 text-xs text-slate-200">
                <input type="checkbox" checked={reset.has(a.entity)} onChange={() => toggle(reset, a.entity, setReset)} className="h-3 w-3" /> <span className="font-mono">{a.entity}</span>
              </label>
            )) : <p className="mt-1 text-[11px] text-slate-400">No account in your register. Add the accounts the attacker used in the Case tab.</p>}
          </fieldset>
          <fieldset className="border-0 p-0">
            <legend className="text-[11px] font-semibold text-slate-300">Indicators to block (your sweeps that hit)</legend>
            {indicators.length ? indicators.map(i => (
              <label key={i} className="mr-3 mt-1 inline-flex items-center gap-1.5 text-xs text-slate-200">
                <input type="checkbox" checked={block.has(i)} onChange={() => toggle(block, i, setBlock)} className="h-3 w-3" /> <span className="font-mono">{i}</span>
              </label>
            )) : <p className="mt-1 text-[11px] text-slate-400">No sweep with hits yet.</p>}
          </fieldset>
          <label className="block text-[11px] font-semibold text-slate-300">Detection proposal: a search that would have caught it earlier
            <input value={detection} onChange={e => setDetection(e.target.value)} maxLength={300} placeholder="e.g. powershell -enc   or   dst:193.106.191.42   (fields: host: user: dst: src: event: source:)" className={`${box} mt-1 w-full font-mono text-xs`} />
          </label>
          {detection.trim().length >= 3 && (
            <p className="text-[11px] text-slate-300" aria-live="polite">Matches <strong>{preview.rows}</strong> log{preview.rows === 1 ? "" : "s"} in the feed so far{preview.hosts.length ? ` on ${preview.hosts.slice(0, 5).join(", ")}${preview.hosts.length > 5 ? " and more" : ""}` : ""}. A good rule catches the attack and little else.{preview.hosts.some(h => !hosts.some(c => c.key === hostKey(h))) && " Some hits are outside your confirmed scope: check they are not ordinary activity."}</p>
          )}
          <label className="block text-[11px] font-semibold text-slate-300">Notes (optional)
            <textarea value={notes} onChange={e => setNotes(e.target.value)} rows={2} maxLength={1000} className={`${box} mt-1 w-full text-xs`} placeholder="e.g. memory was lost on WS-047 (process killed before capture), so the loader hash is unknown" />
          </label>
          {err && <p role="alert" className="text-[11px] text-neon-amber">{err}</p>}
          <Button variant="primary" size="sm" disabled={busy || !open} onClick={() => void submit()}>Send close-out</Button>
        </fieldset>
      </div>
    </Card>
  );
}
