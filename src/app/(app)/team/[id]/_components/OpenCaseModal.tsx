"use client";
import { useRef, useState } from "react";
import { FolderPlus, X } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { asStr, type ActR } from "@/lib/team/format";
import type { Ev } from "@/lib/team/types";

const SEVERITIES = ["low", "medium", "high", "critical"] as const;

/**
 * Tier-2 / Tier-3 open a case on a log they found themselves (in the feed, or on a hunt):
 * the same escalation.requested Tier-1 sends (0092 lets t2/t3 send it), acknowledged by the
 * opener right away so the case is theirs from the start. It then appears in the case queue
 * and the Shared Case like any escalation.
 */
export function OpenCaseModal({ log, role, onClose, act, actR }: {
  log: Ev; role: "t2" | "t3"; onClose: () => void;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>; actR: ActR;
}) {
  const p = log.payload as { id?: string; description?: unknown; hostname?: unknown; user_email?: unknown; severity?: unknown; source?: unknown };
  const eventId = String(p.id ?? log.seq);
  const sev0 = asStr(p.severity);
  const [summary, setSummary] = useState("");
  const [observations, setObservations] = useState("");
  const [severity, setSeverity] = useState<string>((SEVERITIES as readonly string[]).includes(sev0) ? sev0 : "medium");
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useFocusTrap(true, ref, { onEscape: onClose });
  const ready = summary.trim().length >= 4 && observations.trim().length >= 4;

  async function submit() {
    if (!ready || busy) return;
    setBusy(true);
    const host = asStr(p.hostname), user = asStr(p.user_email);
    const res = await actR("escalation.requested", {
      event_id: eventId, summary: summary.trim(), observations: observations.trim(), assessment: "",
      iocs: [], requested_action: "investigate", severity, confidence: 0.7,
      hostname: host || undefined, entity: host || user || "the affected asset",
      opened_by: role, what: summary.trim(), why: observations.trim(),
    });
    if (res.ok) await act("escalation.acknowledged", { event_id: eventId });
    setBusy(false);
    if (res.ok) onClose();
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
          The case opens in the queue and in the Shared Case, already acknowledged by you, so you own it. Investigate, set the scope, and request containment as usual.
        </p>
        <input id="open-case-summary" aria-label="Summary" value={summary} onChange={e => setSummary(e.target.value)} maxLength={300}
          placeholder="Summary: one line, what happened and on what"
          className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <textarea id="open-case-observations" aria-label="Observations" value={observations} onChange={e => setObservations(e.target.value)} rows={3} maxLength={4000}
          placeholder={role === "t3" ? "What your hunt found: the hypothesis, the evidence, the technique" : "Why this log is an incident: the evidence you see"}
          className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <select id="open-case-severity" aria-label="Severity" value={severity} onChange={e => setSeverity(e.target.value)}
          className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
          {SEVERITIES.map(s => <option key={s} value={s}>severity: {s}</option>)}
        </select>
        <div className="flex gap-2">
          <Button variant="outline" className="flex-1" onClick={onClose}>Cancel</Button>
          <Button className="flex-1" disabled={!ready || busy} onClick={submit}>{busy ? "Opening…" : "Open case"}</Button>
        </div>
      </div>
    </div>
  );
}
