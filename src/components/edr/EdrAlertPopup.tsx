"use client";
/**
 * The red "new detection" alert of the live EDR console — what Falcon / Defender pop when a
 * sensor fires: the detection, the host, the process with its full command line, hash,
 * signer and ancestry, its network / file activity, and what the sensor did about it.
 * Everything comes from the investigation (which is built only from logs already in the
 * SIEM feed); nothing reveals the answer (no verdict, no "why it stands out" note).
 */
import { useRef } from "react";
import { Siren, Cpu, X, ChevronRight } from "lucide-react";
import type { EdrDetection, EdrInvestigation, EdrProcess } from "@/lib/edr/investigations";
import { techniqueById, tacticById } from "@/lib/mitre/attack";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";

export interface EdrAlert { key: string; inv: EdrInvestigation; d: EdrDetection }

/** The process and its parents up to the root (oldest first). */
function ancestry(inv: EdrInvestigation, pid: number): EdrProcess[] {
  const chain: EdrProcess[] = [];
  const seen = new Set<number>();
  let p = inv.processes.find(x => x.pid === pid);
  while (p && !seen.has(p.pid) && chain.length < 8) {
    chain.unshift(p);
    seen.add(p.pid);
    const ppid = p.ppid;
    p = ppid ? inv.processes.find(x => x.pid === ppid) : undefined;
  }
  return chain;
}

/** What the sensor did: prevention detections name it, everything else is detect-only. */
function actionTaken(d: EdrDetection): string {
  const s = `${d.technique} ${d.name} ${d.ioa ?? ""}`;
  if (/quarantin/i.test(s)) return "File quarantined";
  if (/kill|terminat/i.test(s)) return "Process killed";
  if (/block|prevent|denied/i.test(s)) return "Blocked";
  return "Detected (no automatic action)";
}

const SEV: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-neon-amber text-black",
  low: "bg-slate-500 text-white",
};

function Row({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[8.5rem_1fr] gap-2 py-1 text-xs">
      <dt className="text-slate-400">{label}</dt>
      <dd className={`min-w-0 break-words text-slate-100 ${mono ? "font-mono text-[11px]" : ""}`}>{children}</dd>
    </div>
  );
}

export function EdrAlertPopup({ alert, index, total, onInvestigate, onAcknowledge }: {
  alert: EdrAlert;
  index: number;
  total: number;
  onInvestigate: () => void;
  onAcknowledge: () => void;
}) {
  const { inv, d } = alert;
  const ref = useRef<HTMLDivElement>(null);
  const investigateRef = useRef<HTMLButtonElement>(null);
  useFocusTrap(true, ref, { onEscape: onAcknowledge, initialFocus: investigateRef });

  const proc = inv.processes.find(p => p.pid === d.pid);
  const chain = ancestry(inv, d.pid);
  const tech = /^T\d{4}/.test(d.technique) ? techniqueById(d.technique) : undefined;
  const tactic = tech ? tacticById(tech.tactic) : undefined;
  const at = inv.timeline.find(t => t.kind === "detection" && t.pid === d.pid)?.at
    ?? inv.timeline.find(t => t.pid === d.pid)?.at ?? proc?.startedAt ?? "—";
  const net = proc?.network ?? [];
  const files = proc?.files ?? [];

  return (
    <div className="fixed inset-0 z-[80] flex items-start justify-center overflow-y-auto bg-black/70 p-4 pt-[6vh] backdrop-blur-sm">
      <div ref={ref} role="alertdialog" aria-modal="true" aria-labelledby="edr-alert-title" aria-describedby="edr-alert-what"
        className="w-full max-w-2xl overflow-hidden rounded-xl border-2 border-severity-critical/70 bg-bg-elevated shadow-[0_0_60px_-10px_rgba(255,45,85,0.6)]">
        {/* Header */}
        <div className="flex items-center gap-3 bg-severity-critical/90 px-4 py-3 text-white">
          <Siren className="h-5 w-5 shrink-0 animate-pulse motion-reduce:animate-none" aria-hidden="true" />
          <div className="min-w-0 flex-1">
            <p id="edr-alert-title" className="text-sm font-bold uppercase tracking-wider">New EDR detection</p>
            <p className="truncate text-[11px] opacity-90">{inv.edrAgent?.display ?? "Endpoint sensor"} · {inv.host.name} · {at}</p>
          </div>
          {total > 1 && <span className="rounded-full bg-black/25 px-2 py-0.5 text-[10px] font-semibold">{index + 1} of {total}</span>}
          <button onClick={onAcknowledge} aria-label="Acknowledge alert" className="rounded p-1 hover:bg-black/20">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-[70vh] space-y-4 overflow-y-auto px-4 py-4">
          {/* Detection */}
          <section aria-label="Detection">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${SEV[d.severity] ?? SEV.high}`}>{d.severity}</span>
              {tech && <span className="rounded border border-neon-purple/40 bg-neon-purple/10 px-1.5 py-0.5 font-mono text-[10px] font-bold text-neon-purple">{d.technique}</span>}
              <span className="text-[11px] text-slate-400">{actionTaken(d)}</span>
            </div>
            <p id="edr-alert-what" className="mt-2 text-base font-bold text-white">{d.name}</p>
            {d.ioa && <p className="mt-1 text-[13px] leading-relaxed text-slate-300">{d.ioa}</p>}
            <dl className="mt-2 divide-y divide-border/50">
              {tech && <Row label="Technique">{tech.name}</Row>}
              {tactic && <Row label="Tactic">{tactic.name} ({tactic.id})</Row>}
              <Row label="Detected at" mono>{at}</Row>
            </dl>
          </section>

          {/* Host */}
          <section aria-label="Host" className="rounded-lg border border-border bg-bg p-3">
            <p className="mb-1 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500"><Cpu className="h-3 w-3" /> Host</p>
            <dl className="divide-y divide-border/50">
              <Row label="Hostname" mono>{inv.host.name}</Row>
              <Row label="IP address" mono>{inv.host.ip}</Row>
              <Row label="OS">{inv.host.os}</Row>
              <Row label="Signed-in user" mono>{inv.host.user}</Row>
              {inv.edrAgent && <Row label="Sensor">{inv.edrAgent.display}</Row>}
            </dl>
          </section>

          {/* Process */}
          {proc && (
            <section aria-label="Process" className="rounded-lg border border-border bg-bg p-3">
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Triggering process</p>
              <dl className="divide-y divide-border/50">
                <Row label="Process" mono>{proc.name} (PID {proc.pid})</Row>
                <Row label="Image path" mono>{proc.path}</Row>
                <Row label="Command line" mono>{proc.cmdline}</Row>
                <Row label="User" mono>{proc.user}</Row>
                {proc.sha256 && <Row label="SHA256" mono>{proc.sha256}</Row>}
                <Row label="Signature">{proc.signed ? "Signed" : "Unsigned"}</Row>
                {proc.originalFileName && <Row label="Original file name" mono>{proc.originalFileName}</Row>}
                <Row label="Started" mono>{proc.startedAt}</Row>
                {chain.length > 1 && (
                  <Row label="Process tree" mono>
                    <span className="flex flex-wrap items-center gap-1">
                      {chain.map((p, i) => (
                        <span key={p.pid} className="inline-flex items-center gap-1">
                          {i > 0 && <ChevronRight className="h-3 w-3 text-slate-500" aria-hidden="true" />}
                          <span className={p.pid === proc.pid ? "font-bold text-severity-critical" : ""}>{p.name}</span>
                          <span className="text-slate-500">({p.pid})</span>
                        </span>
                      ))}
                    </span>
                  </Row>
                )}
              </dl>
            </section>
          )}

          {/* Activity */}
          {(net.length > 0 || files.length > 0) && (
            <section aria-label="Process activity" className="rounded-lg border border-border bg-bg p-3">
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Process activity</p>
              <ul className="space-y-1 font-mono text-[11px] text-slate-300">
                {net.slice(0, 4).map((c, i) => (
                  <li key={`n${i}`}>{c.ts} · {c.direction} · {c.domain ? `${c.domain} ` : ""}{c.remote_ip}:{c.remote_port}{c.application ? ` (${c.application})` : c.proto ? ` (${c.proto})` : ""}</li>
                ))}
                {files.slice(0, 4).map((f, i) => (
                  <li key={`f${i}`}>{f.ts} · file {f.action} · {f.path}</li>
                ))}
              </ul>
            </section>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border bg-bg px-4 py-3">
          <button onClick={onAcknowledge} className="rounded-md border border-border px-3 py-1.5 text-xs font-semibold text-slate-300 hover:text-white">Acknowledge</button>
          <button ref={investigateRef} onClick={onInvestigate}
            className="inline-flex items-center gap-1.5 rounded-md bg-severity-critical px-3.5 py-1.5 text-xs font-bold text-white hover:brightness-110">
            Investigate in the process tree <ChevronRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * The default, non-blocking form of a live alert: a compact red card per new detection in
 * the corner (the console stays usable underneath), with Details for the full panel above.
 */
export function EdrAlertToasts({ alerts, onDetails, onInvestigate, onAcknowledge }: {
  alerts: EdrAlert[];
  onDetails: (a: EdrAlert) => void;
  onInvestigate: (a: EdrAlert) => void;
  onAcknowledge: (a: EdrAlert) => void;
}) {
  if (alerts.length === 0) return null;
  const shown = alerts.slice(0, 3);
  return (
    <div role="status" aria-live="polite" className="fixed bottom-16 right-4 z-[70] flex w-[min(92vw,22rem)] flex-col gap-2">
      {shown.map(a => {
        const proc = a.inv.processes.find(p => p.pid === a.d.pid);
        const at = a.inv.timeline.find(t => t.kind === "detection" && t.pid === a.d.pid)?.at ?? proc?.startedAt ?? "";
        return (
          <div key={a.key} className="overflow-hidden rounded-lg border border-severity-critical/60 bg-bg-elevated shadow-[0_0_30px_-8px_rgba(255,45,85,0.55)]">
            <div className="flex items-center gap-2 bg-severity-critical/90 px-3 py-1.5 text-white">
              <Siren className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <p className="flex-1 truncate text-[11px] font-bold uppercase tracking-wider">EDR detection · {a.d.severity}</p>
              {at && <span className="font-mono text-[10px] opacity-90">{at}</span>}
              <button onClick={() => onAcknowledge(a)} aria-label={`Acknowledge ${a.d.name}`} className="rounded p-0.5 hover:bg-black/20"><X className="h-3.5 w-3.5" /></button>
            </div>
            <div className="px-3 py-2">
              <p className="truncate text-xs font-semibold text-white" title={a.d.name}>{a.d.name}</p>
              <p className="mt-0.5 truncate font-mono text-[10px] text-slate-400">
                {a.inv.host.name}{proc ? ` · ${proc.name} (${proc.pid})` : ""}{/^T\d{4}/.test(a.d.technique) ? ` · ${a.d.technique}` : ""}
              </p>
              <div className="mt-2 flex justify-end gap-2">
                <button onClick={() => onDetails(a)} className="rounded border border-border px-2 py-1 text-[11px] font-semibold text-slate-300 hover:text-white">Details</button>
                <button onClick={() => onInvestigate(a)} className="rounded bg-severity-critical px-2 py-1 text-[11px] font-bold text-white hover:brightness-110">Investigate</button>
              </div>
            </div>
          </div>
        );
      })}
      {alerts.length > shown.length && (
        <p className="rounded-md border border-severity-critical/40 bg-bg-elevated px-3 py-1.5 text-center text-[11px] font-semibold text-severity-critical">
          +{alerts.length - shown.length} more detection{alerts.length - shown.length > 1 ? "s" : ""}
        </p>
      )}
    </div>
  );
}
