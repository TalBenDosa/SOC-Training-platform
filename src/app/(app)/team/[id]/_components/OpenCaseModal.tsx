"use client";
import { useRef, useState } from "react";
import { FolderPlus, X } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { asStr, detectIocType, isValidIoc, IOC_HELP, type ActR } from "@/lib/team/format";
import type { Ev, Ioc } from "@/lib/team/types";
import { useDraft, clearDraft } from "./drafts";
import { escalationSnapshot } from "@/lib/team/handoff";

const SEVERITIES = ["low", "medium", "high", "critical"] as const;

/**
 * Tier-2 / Tier-3 open a case on a log they found themselves (in the feed, or on a hunt):
 * the same escalation.requested Tier-1 sends (0092 lets t2/t3 send it), acknowledged by the
 * opener right away so the case is theirs from the start. It then appears in the case queue
 * and the Shared Case like any escalation. It is marked self-opened (opened_by) everywhere it shows,
 * and it carries the indicators the analyst picks (2026-11 review: every case had `iocs: []`).
 */

/** Indicator candidates straight from the log's own fields: one click adds one. */
export function iocCandidates(payload: Record<string, unknown>): string[] {
  const out: string[] = [];
  const add = (v: unknown) => { if (typeof v === "string" && v.trim() && v.length <= 200 && !out.includes(v.trim())) out.push(v.trim()); };
  const p = payload as Record<string, unknown> & { user?: { email?: unknown }; process?: { sha256?: unknown; hash?: unknown }; file?: { sha256?: unknown } };
  for (const k of ["src_ip", "dst_ip", "remote_ip", "domain", "dns_query", "url", "sha256", "file_hash", "hash", "user_email", "hostname"]) add(p[k]);
  add(p.user?.email); add(p.process?.sha256); add(p.process?.hash); add(p.file?.sha256);
  return out.slice(0, 10);
}
export function OpenCaseModal({ log, role, onClose, act, actR, sessionId, meId }: {
  log: Ev; role: "t2" | "t3"; onClose: () => void; sessionId?: string; meId?: string;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>; actR: ActR;
}) {
  const p = log.payload as { id?: string; description?: unknown; hostname?: unknown; user_email?: unknown; severity?: unknown; source?: unknown };
  const eventId = String(p.id ?? log.seq);
  const sev0 = asStr(p.severity);
  const [summary, setSummary] = useState("");
  const [observations, setObservations] = useState("");
  const [severity, setSeverity] = useState<string>((SEVERITIES as readonly string[]).includes(sev0) ? sev0 : "medium");
  const [busy, setBusy] = useState(false);
  const [iocs, setIocs] = useState<Ioc[]>([]);
  const [iocText, setIocText] = useState("");
  const [iocErr, setIocErr] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const picks = iocCandidates(log.payload).filter(v => !iocs.some(i => i.value.toLowerCase() === v.toLowerCase()));
  function addIoc(v0: string, source: "picked" | "manual") {
    const v = v0.trim(); if (!v) return;
    if (source === "manual" && !isValidIoc(v)) { setIocErr(`"${v.slice(0, 80)}" is not a valid indicator (${IOC_HELP}).`); return; }
    setIocErr("");
    setIocs(d => (d.some(x => x.value.toLowerCase() === v.toLowerCase()) ? d : [...d, { type: detectIocType(v), value: v, source }]));
  }
  useDraft(sessionId, meId, `open-case-${eventId}`, `Case you were opening on #${log.seq}`, [summary && `Summary: ${summary}`, observations && `Observations: ${observations}`].filter(Boolean).join("\n"));
  const ref = useRef<HTMLDivElement>(null);
  useFocusTrap(true, ref, { onEscape: onClose });
  const ready = summary.trim().length >= 4 && observations.trim().length >= 4;

  async function submit() {
    if (!ready || busy) return;
    setBusy(true);
    const host = asStr(p.hostname), user = asStr(p.user_email);
    const res = await actR("escalation.requested", {
      event_id: eventId, summary: summary.trim(), observations: observations.trim(), assessment: "",
      iocs, requested_action: "investigate", severity, confidence: 0.7,
      hostname: host || undefined, entity: host || user || "the affected asset",
      opened_by: role, what: summary.trim(), why: observations.trim(),
      // The log travels with the case like a Tier-1 escalation, so every receiver (the Manager, the
      // Shared case, Sentinel) opens it with the log's key fields, not only the opener's words.
      snapshot: escalationSnapshot(log.payload), user_email: user || undefined,
    });
    if (res.ok) await act("escalation.acknowledged", { event_id: eventId });
    setBusy(false);
    if (!res.ok) { setErr(res.message ?? "The case could not be opened. Try again."); return; }
    if (sessionId && meId) clearDraft(sessionId, meId, `open-case-${eventId}`);
    onClose();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4" onClick={onClose}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="open-case-title" onClick={e => e.stopPropagation()}
        className="w-full max-w-lg space-y-3 rounded-xl border border-border bg-bg-elevated p-4 shadow-2xl">
        <div className="flex items-center justify-between gap-2">
          <h2 id="open-case-title" className="flex items-center gap-2 text-base font-semibold text-white">
            <FolderPlus className="h-4 w-4 text-cyber-300" aria-hidden /> Open a case on this log
          </h2>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded p-1 text-slate-400 hover:bg-white/5 hover:text-white"><X className="h-4 w-4" /></button>
        </div>
        <div className="rounded-lg border border-border bg-bg px-3 py-2 text-xs text-slate-300">
          <span className="text-slate-500">#{log.seq} · {asStr(p.source) || "log"}</span>
          <p className="mt-0.5 text-sm text-slate-200">{asStr(p.description) || "event"}</p>
        </div>
        <p className="text-[11px] text-slate-400">
          The case opens in the queue and in the Shared case, marked as opened by you, and you own it. Its steps then guide you: investigate, report, scope, contain, resolve.
        </p>
        <input id="open-case-summary" aria-label="Summary" value={summary} onChange={e => setSummary(e.target.value)} maxLength={300}
          placeholder="Summary: one line, what happened and on what"
          className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <textarea id="open-case-observations" aria-label="Observations" value={observations} onChange={e => setObservations(e.target.value)} rows={3} maxLength={4000}
          placeholder={role === "t3" ? "What your hunt found: the hypothesis, the evidence, the technique" : "Why this log is an incident: the evidence you see"}
          className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <div className="rounded-lg border border-border bg-bg px-2 py-1.5">
          <p className="text-[11px] font-semibold text-slate-300">Indicators (IOCs)</p>
          {iocs.length > 0 && (
            <ul className="mt-1 flex flex-wrap gap-1" aria-label="Indicators on this case">
              {iocs.map(i => (
                <li key={i.value} className="inline-flex items-center gap-1 rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 font-mono text-[11px] text-cyber-200">
                  <span className="text-slate-400">{i.type}:</span><bdi>{i.value}</bdi>
                  <button type="button" onClick={() => setIocs(d => d.filter(x => x.value !== i.value))} aria-label={`Remove indicator ${i.value}`} className="rounded text-slate-400 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50"><X className="h-3 w-3" aria-hidden /></button>
                </li>
              ))}
            </ul>
          )}
          {picks.length > 0 && (
            <div className="mt-1 flex flex-wrap items-center gap-1">
              <span className="text-[11px] text-slate-400">From this log:</span>
              {picks.map(v => <button key={v} type="button" onClick={() => addIoc(v, "picked")} className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px] text-slate-300 hover:border-cyber-500/50 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50">+ <bdi>{v}</bdi></button>)}
            </div>
          )}
          <div className="mt-1 flex gap-1.5">
            <input aria-label="Add an indicator" value={iocText} onChange={e => setIocText(e.target.value)} onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addIoc(iocText, "manual"); setIocText(""); } }}
              placeholder="Add an indicator (IP, domain, hash, account)"
              className="min-w-0 flex-1 rounded border border-border bg-bg-elevated px-2 py-1 font-mono text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            <Button variant="outline" size="sm" onClick={() => { addIoc(iocText, "manual"); setIocText(""); }}>Add</Button>
          </div>
          {iocErr && <p role="alert" className="mt-1 text-[11px] text-severity-high">{iocErr}</p>}
        </div>
        <select id="open-case-severity" aria-label="Severity" value={severity} onChange={e => setSeverity(e.target.value)}
          className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
          {SEVERITIES.map(s => <option key={s} value={s}>severity: {s}</option>)}
        </select>
        {err && <p role="alert" className="text-[11px] text-neon-amber">{err}</p>}
        <div className="flex gap-2">
          <Button variant="outline" className="flex-1" onClick={onClose}>Cancel</Button>
          <Button className="flex-1" disabled={!ready || busy} onClick={submit}>{busy ? "Opening…" : "Open case"}</Button>
        </div>
      </div>
    </div>
  );
}
