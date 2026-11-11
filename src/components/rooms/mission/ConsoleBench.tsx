"use client";
/**
 * A console step: the job in a checklist, the console one click away (full screen,
 * with the mission card floating over it so the learner never loses the task),
 * and the facts typed in the same card. The console is the XDR console of the
 * team exercises, our own design, loaded with the room's workspace.
 */
import dynamic from "next/dynamic";
import { useEffect, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { ArrowLeftRight, ChevronDown, ChevronUp, ListChecks, MonitorUp, RotateCcw } from "lucide-react";
import { cn } from "@/lib/utils";
import type { SanitizedStep } from "@/lib/missions/sanitize";
import { Button } from "@/components/ui/Button";
import { InlineMd } from "../InlineMd";
import { FieldsBench } from "./Benches";
import type { MissionConsoleHandle } from "./useMissionConsole";

const SentinelConsole = dynamic(() => import("@/components/sentinel/SentinelConsole").then(m => m.SentinelConsole), {
  ssr: false,
  loading: () => <div className="fixed inset-0 z-[9000] grid place-items-center bg-[#0b1220] text-sm text-slate-300">Opening the console...</div>,
});

type ConsoleStepView = Extract<SanitizedStep, { kind: "console" }>;

function Todo({ items }: { items: string[] }) {
  return (
    <ol className="list-inside list-decimal space-y-1 text-sm text-slate-200">
      {items.map((t, i) => <li key={i}><InlineMd text={t} /></li>)}
    </ol>
  );
}

export function ConsoleBench({ step, stepNo, handle, values, onValues, verdicts, disabled, controls }: {
  step: ConsoleStepView;
  stepNo: number;
  handle: MissionConsoleHandle;
  values: Record<string, string>;
  onValues: (v: Record<string, string>) => void;
  verdicts?: { id: string; ok: boolean; say?: string }[];
  disabled: boolean;
  /** The help ladder, feedback and Check button: shown in the floating card while the console is open. */
  controls: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [folded, setFolded] = useState(false);
  // The card moves aside when it covers what the learner is reading (a side panel's buttons, the menu).
  const [side, setSide] = useState<"left" | "right">("right");
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const ws = handle.workspace;
  const numbers = step.checksIncidents.map(id => id.replace(/^inc-/, ""));

  return (
    <div className="space-y-3">
      <div className="space-y-3 rounded-lg border border-violet-400/30 bg-violet-500/5 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <ListChecks className="h-4 w-4 text-violet-300" aria-hidden />
          <p className="text-sm font-semibold text-white">In the console</p>
          {numbers.length > 0 && <span className="text-xs text-slate-400">The check reads incident {numbers.join(" and ")} as you leave it.</span>}
        </div>
        <Todo items={step.todo} />
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary" size="md" disabled={!ws} onClick={() => { setOpen(true); setFolded(false); }}>
            <MonitorUp className="h-4 w-4" /> {ws ? "Open the console" : handle.error ? "Console unavailable" : "Loading the console..."}
          </Button>
          {handle.error && <button type="button" className="text-sm text-neon-amber underline" onClick={handle.retry}>{handle.error} Try again</button>}
          <button type="button" className="ml-auto inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200"
            onClick={() => { if (window.confirm("Put every incident back as you found it? Your owners, statuses, comments and bookmarks in this room's console are removed.")) handle.reset(); }}>
            <RotateCcw className="h-3.5 w-3.5" aria-hidden /> Reset the console
          </button>
        </div>
      </div>
      {step.fields.length > 0 && (
        <FieldsBench fields={step.fields} values={values} onChange={onValues} verdicts={verdicts} disabled={disabled} />
      )}

      {open && ws && mounted && createPortal(
        <>
          <SentinelConsole
            workspace={ws} states={handle.states} actions={handle.actions} onRefresh={() => {}} ended={false}
            backHref="#" backLabel="Back to the mission" onBack={() => setOpen(false)} savedBookmarks={handle.loose}
            initial={step.open?.incidentId ? { incidentId: step.open.incidentId } : undefined}
            initialScreen={step.open?.screen}
          />
          {/* data-sentinel-keep: the console marks everything else on the page inert, but not the mission card. */}
          <aside data-sentinel-keep aria-label={`Mission card, step ${stepNo}`}
            className={cn("fixed bottom-4 z-[9500] overflow-hidden rounded-xl border border-violet-400/50 bg-[#0d1424] text-slate-200 shadow-2xl shadow-black/60",
              side === "right" ? "right-4" : "left-4", folded ? "w-auto" : "w-[min(400px,calc(100vw-2rem))]")}>
            <div className={cn("flex items-center gap-2 px-3 py-2", !folded && "border-b border-white/10")}>
              <ListChecks className="h-4 w-4 text-violet-300" aria-hidden />
              <p className="text-sm font-semibold text-white">{folded ? `Step ${stepNo}` : `Mission card: step ${stepNo}`}</p>
              <button type="button" className="ml-auto rounded p-1 text-slate-300 hover:bg-white/10"
                aria-label={side === "right" ? "Move the mission card to the left" : "Move the mission card to the right"}
                onClick={() => setSide(s => (s === "right" ? "left" : "right"))}>
                <ArrowLeftRight className="h-4 w-4" aria-hidden />
              </button>
              <button type="button" className="rounded p-1 text-slate-300 hover:bg-white/10" aria-expanded={!folded}
                aria-label={folded ? "Show the mission card" : "Fold the mission card"} onClick={() => setFolded(f => !f)}>
                {folded ? <ChevronUp className="h-4 w-4" aria-hidden /> : <ChevronDown className="h-4 w-4" aria-hidden />}
              </button>
            </div>
            {!folded && (
              <div className="max-h-[min(70vh,640px)] space-y-3 overflow-y-auto p-3">
                <p className="text-sm leading-relaxed text-white"><InlineMd text={step.prompt} /></p>
                <Todo items={step.todo} />
                {step.fields.length > 0 && (
                  <FieldsBench fields={step.fields} values={values} onChange={onValues} verdicts={verdicts} disabled={disabled} />
                )}
                {controls}
              </div>
            )}
          </aside>
        </>,
        document.body,
      )}
    </div>
  );
}
