"use client";
/**
 * WorkflowGuide — the persistent "what do I do now?" strip.
 *
 * There is deliberately only ONE tracked, gradeable step: the Incident Report.
 * Watching the feed and forming a hypothesis happens silently, with no
 * checkbox, no per-row grading, and no hint about which event is the attack —
 * the report itself is the only place the analyst's findings are assessed.
 */
import { useState } from "react";
import { cn } from "@/lib/utils";
import { CheckCircle2, Circle } from "lucide-react";
import { Term } from "@/components/ui/Term";

interface Props {
  reportPassed: boolean;
}

export function WorkflowGuide({ reportPassed }: Props) {
  const [open, setOpen] = useState(false);

  return (
    <div className={cn(
      "rounded-lg border px-4 py-2.5",
      reportPassed ? "border-neon-green/40 bg-neon-green/5" : "border-cyber-500/25 bg-cyber-500/[0.04]"
    )}>
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-[9px] font-bold uppercase tracking-[0.2em] text-slate-500">
          Analyst Workflow
        </span>

        <span className="text-[11px] text-slate-400">
          Investigate the feed — read the logs, no hints, decide for yourself.
        </span>

        <span className="text-slate-700">→</span>

        <button
          onClick={() => setOpen(v => !v)}
          className={cn(
            "flex items-center gap-1.5 rounded px-2 py-1 text-[11px] font-semibold transition",
            reportPassed ? "text-neon-green hover:bg-neon-green/10" : "text-cyber-300 hover:bg-cyber-500/10"
          )}
        >
          {reportPassed
            ? <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
            : <Circle className="h-3.5 w-3.5 shrink-0 animate-pulse text-cyber-400" />
          }
          <span className={cn(reportPassed && "line-through decoration-neon-green/50")}>
            Report the incident
          </span>
        </button>

        {reportPassed && (
          <span className="ml-auto text-[11px] font-bold text-neon-green">
            Objective complete — end the session to secure the company 🏆
          </span>
        )}
      </div>

      {open && (
        <div className="mt-2 rounded border border-border/50 bg-[#060b12] px-3 py-2">
          <p className="text-[11px] leading-relaxed text-slate-300">
            Press <span className="font-bold text-neon-purple">Report Incident</span> in the top bar and
            describe: what attack happened, which <Term k="ioc">IOCs</Term> (IPs, users, hosts you read in
            the logs) prove it, what action to take, and the business impact. Score 60+ passes.
          </p>
        </div>
      )}
    </div>
  );
}
