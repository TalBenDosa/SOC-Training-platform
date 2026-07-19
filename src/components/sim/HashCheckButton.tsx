"use client";

import { useState } from "react";
import { Shield, Loader2, AlertTriangle, CheckCircle2, HelpCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import type { IOC } from "@/lib/sim/types";
import { resolveHashVerdict, verdictColor, verdictLabel } from "@/lib/sim/hashVerdict";

/**
 * "Check Hash" affordance for a SHA256 shown in a scenario log.
 *
 * Deliberately shows a short lookup delay before the verdict: submitting a hash
 * to a feed is not instant, and an answer that appears the moment you click
 * trains students to treat enrichment as free. It also keeps the analyst's
 * attention on the panel that follows.
 */
export function HashCheckButton({
  hash,
  iocs,
  compact = false,
}: {
  hash: string;
  iocs?: IOC[];
  compact?: boolean;
}) {
  const [state, setState] = useState<"idle" | "checking" | "done">("idle");

  // Only compute verdict when truly done, not on every render
  const [verdict, setVerdict] = useState<ReturnType<typeof resolveHashVerdict> | null>(null);

  function run(e: React.MouseEvent) {
    e.stopPropagation();
    if (state !== "idle") return;
    setState("checking");
    setTimeout(() => {
      setVerdict(resolveHashVerdict(hash, iocs));
      setState("done");
    }, 650);
  }

  if (state === "idle" || state === "checking") {
    return (
      <button
        onClick={run}
        disabled={state === "checking"}
        className={cn(
          "inline-flex w-fit items-center gap-1 rounded border border-neon-amber/50 bg-neon-amber/10 font-bold text-neon-amber transition hover:bg-neon-amber/20 disabled:opacity-70",
          compact ? "px-2 py-0.5 text-[9px]" : "px-3 py-1 text-[10px]",
        )}
      >
        {state === "checking" ? (
          <>
            <Loader2 className={cn("animate-spin", compact ? "h-2.5 w-2.5" : "h-3 w-3")} />
            Querying threat intel…
          </>
        ) : (
          <>
            <Shield className={cn(compact ? "h-2.5 w-2.5" : "h-3 w-3")} />
            Check Hash · Threat Intel
          </>
        )}
      </button>
    );
  }

  if (!verdict) return null;
  const result = verdict;

  const Icon =
    result.verdict === "malicious" ? AlertTriangle
    : result.verdict === "clean"   ? CheckCircle2
    : HelpCircle;

  const ratio = result.detections / result.total;
  const barColor =
    result.verdict === "malicious"  ? "bg-severity-critical"
    : result.verdict === "suspicious" ? "bg-severity-medium"
    : "bg-neon-green";

  return (
    <div
      onClick={e => e.stopPropagation()}
      className={cn(
        "mt-1 w-full max-w-2xl rounded border bg-[#0a0f18] px-3 py-2.5",
        result.verdict === "malicious"  ? "border-severity-critical/50"
        : result.verdict === "suspicious" ? "border-severity-medium/50"
        : "border-neon-green/40",
      )}
    >
      <div className="flex items-center gap-2">
        <Icon className={cn("h-3.5 w-3.5 shrink-0", verdictColor(result.verdict))} />
        <span className={cn("text-[11px] font-bold tracking-wide", verdictColor(result.verdict))}>
          {verdictLabel(result.verdict)}
        </span>
        <span className="text-[10px] text-slate-400">·</span>
        <span className="font-mono text-[10px] text-slate-300">
          {result.detections}/{result.total} engines
        </span>
      </div>

      {/* detection ratio */}
      <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-slate-700/50">
        <div className={cn("h-full rounded-full", barColor)} style={{ width: `${Math.max(ratio * 100, 2)}%` }} />
      </div>

      <dl className="mt-2 space-y-0.5">
        <Row label="File" value={result.name} />
        {result.family && <Row label="Family" value={result.family} />}
        {result.firstSeen && <Row label="First seen" value={result.firstSeen} />}
        <Row label="Source" value={result.source} />
      </dl>

      {result.tags.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-1">
          {result.tags.map(t => (
            <span key={t} className="rounded bg-slate-700/50 px-1.5 py-0.5 font-mono text-[9px] text-slate-300">
              {t}
            </span>
          ))}
        </div>
      )}

      <p className="mt-2 border-t border-border/40 pt-2 text-[10px] leading-relaxed text-slate-400">
        {result.rationale}
      </p>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <dt className="w-20 shrink-0 text-[10px] text-slate-500">{label}</dt>
      <dd className="text-[10px] text-slate-300 break-words">{value}</dd>
    </div>
  );
}

/** Does this field hold a SHA256 worth offering a lookup on? */
export function isHashField(key: string, val: string): boolean {
  if (!/^[a-f0-9]{64}$/i.test(val)) return false;
  const k = key.toLowerCase();
  return (
    k === "file.hash.sha256" ||
    k.endsWith(".sha256") ||
    k.endsWith("sha256hashdata") ||   // CrowdStrike  SHA256HashData
    k.endsWith("sha256") ||           // Defender / MDE  SHA256
    k.endsWith(".hashes") || k === "hashes"   // Sysmon  Hashes
  );
}
