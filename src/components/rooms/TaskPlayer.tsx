"use client";
import React, { useState, useRef, useEffect, useCallback } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { ChevronRight, CheckCircle2, ChevronDown, Flag, Lightbulb, Tag, X, BookOpen, Shield, FileText } from "lucide-react";
import type {
  SanitizedRoomTask as RoomTask,
  SanitizedReadingTask as ReadingTask,
  SanitizedQuestionTask as QuestionTask,
  SanitizedLogAnalysisTask as LogAnalysisTask,
  SanitizedFlagTask as FlagTask,
  SanitizedAnalystChoiceTask as AnalystChoiceTask,
  SanitizedQueryFillTask as QueryFillTask,
  SanitizedMatchingTask as MatchingTask,
  SanitizedOrderingTask as OrderingTask,
  SanitizedWrittenReportTask as WrittenReportTask,
} from "@/lib/rooms/sanitize";
import type { TelemetryEvent } from "@/lib/sim/types";
import { useTaskTelemetry, type TaskTelemetryEntry } from "@/lib/useTaskTelemetry";
import { MermaidDiagram } from "./MermaidDiagram";
import { LessonFigure } from "@/components/lessons/LessonFigure";

interface TaskPlayerProps {
  roomId: string;
  task: RoomTask;
  onComplete: (xpEarned: number, telemetry?: TaskTelemetryEntry) => void;
  isCompleted: boolean;
  prevLogEvent?: TelemetryEvent;
}

/** POSTs a task submission to the server-side grader (src/lib/rooms/grading.ts)
 *  and returns its verdict. No sub-player ever compares an answer locally
 *  anymore — see src/data/rooms.ts's file doc for why. */
async function submitTask(roomId: string, taskId: string, body: unknown): Promise<{ correct: boolean; xpEarned: number; reveal: Record<string, any> }> {
  const res = await fetch(`/api/rooms/${encodeURIComponent(roomId)}/tasks/${encodeURIComponent(taskId)}/submit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Grading request failed (${res.status})`);
  return res.json();
}

// ─── IOC Types ──────────────────────────────────────────────────────────────────
const IOC_DEFS = [
  { key: "ip",       label: "IP Address",  color: "text-red-400",       bg: "bg-red-500/15",      border: "border-red-500/40"    },
  { key: "domain",   label: "Domain",      color: "text-neon-amber",    bg: "bg-neon-amber/10",   border: "border-neon-amber/30" },
  { key: "hash",     label: "File Hash",   color: "text-purple-400",    bg: "bg-purple-500/10",   border: "border-purple-500/30" },
  { key: "username", label: "Username",    color: "text-cyber-300",     bg: "bg-cyber-500/10",    border: "border-cyber-500/30"  },
  { key: "process",  label: "Process",     color: "text-neon-green",    bg: "bg-neon-green/10",   border: "border-neon-green/30" },
  { key: "path",     label: "File Path",   color: "text-blue-400",      bg: "bg-blue-500/10",     border: "border-blue-500/30"   },
  { key: "email",    label: "Email",       color: "text-orange-400",    bg: "bg-orange-500/10",   border: "border-orange-500/30" },
  { key: "other",    label: "Other IOC",   color: "text-slate-300",     bg: "bg-slate-600/20",    border: "border-slate-500/30"  },
] as const;
type IocType = typeof IOC_DEFS[number]["key"];
interface IocEntry { field: string; value: string; type: IocType; }

function iocDef(type: IocType) {
  return IOC_DEFS.find(d => d.key === type) ?? IOC_DEFS[7];
}

// ─── Source badge colors ────────────────────────────────────────────────────────
const SOURCE_COLORS: Record<string, { border: string; bg: string; text: string; label: string }> = {
  ad:            { border: "border-blue-500/40",    bg: "bg-blue-500/10",    text: "text-blue-400",    label: "Active Directory" },
  edr:           { border: "border-neon-amber/40",  bg: "bg-neon-amber/10",  text: "text-neon-amber",  label: "EDR"              },
  cloudtrail:    { border: "border-orange-500/40",  bg: "bg-orange-500/10",  text: "text-orange-400",  label: "CloudTrail"       },
  email_gateway: { border: "border-purple-500/40",  bg: "bg-purple-500/10",  text: "text-purple-400",  label: "Email Gateway"    },
  o365:          { border: "border-sky-500/40",     bg: "bg-sky-500/10",     text: "text-sky-400",     label: "Microsoft 365"    },
  firewall:      { border: "border-red-500/40",     bg: "bg-red-500/10",     text: "text-red-400",     label: "Firewall"         },
  sysmon:        { border: "border-teal-500/40",    bg: "bg-teal-500/10",    text: "text-teal-400",    label: "Sysmon"           },
  proxy:         { border: "border-lime-500/40",    bg: "bg-lime-500/10",    text: "text-lime-400",    label: "Proxy"            },
  dns:           { border: "border-emerald-500/40", bg: "bg-emerald-500/10", text: "text-emerald-400", label: "DNS"              },
  dlp:           { border: "border-pink-500/40",    bg: "bg-pink-500/10",    text: "text-pink-400",    label: "DLP"              },
  ueba:          { border: "border-violet-500/40",  bg: "bg-violet-500/10",  text: "text-violet-400",  label: "UEBA"             },
  iam:           { border: "border-indigo-500/40",  bg: "bg-indigo-500/10",  text: "text-indigo-400",  label: "IAM"              },
};

// ─── IOC Tag Popover ────────────────────────────────────────────────────────────
interface PopoverState { field: string; value: string; rect: DOMRect; }

function IocTagPopover({
  state, onTag, onClose,
}: { state: PopoverState; onTag: (type: IocType) => void; onClose: () => void; }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [onClose]);

  return (
    <div
      ref={ref}
      className="fixed z-50 bg-[#0d1520] border border-cyber-500/40 rounded-lg shadow-xl shadow-black/60 p-3 w-72"
      style={{ top: state.rect.bottom + 6, left: Math.min(state.rect.left, window.innerWidth - 300) }}
    >
      <p className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold mb-2 px-0.5">Tag as IOC type</p>
      <p className="text-xs text-slate-400 font-mono break-all mb-3 px-0.5 border-l-2 border-cyber-500/40 pl-2">
        {state.value.length > 60 ? state.value.slice(0, 60) + "…" : state.value}
      </p>
      <div className="grid grid-cols-2 gap-1.5">
        {IOC_DEFS.map(d => (
          <button
            key={d.key}
            onClick={() => onTag(d.key)}
            className={cn(
              "rounded-md border px-2 py-1.5 text-left text-xs font-medium transition-all hover:brightness-110",
              d.bg, d.border, d.color,
            )}
          >
            {d.label}
          </button>
        ))}
      </div>
    </div>
  );
}

// ─── IOC Notebook Panel ─────────────────────────────────────────────────────────
function IocNotebook({ iocs, onRemove }: { iocs: IocEntry[]; onRemove: (i: number) => void }) {
  if (iocs.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border/50 px-4 py-5 text-center">
        <BookOpen className="h-5 w-5 text-slate-400 mx-auto mb-2" />
        <p className="text-xs text-slate-400">Click any field value in the log to tag it as an IOC indicator.</p>
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-cyber-500/20 bg-[#080d14] overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-cyber-500/20 bg-cyber-500/5">
        <Shield className="h-3.5 w-3.5 text-cyber-400" />
        <span className="text-[11px] font-bold uppercase tracking-wider text-cyber-400">IOC Notebook</span>
        <span className="ml-auto text-[10px] font-mono text-slate-400">{iocs.length} indicator{iocs.length !== 1 ? "s" : ""}</span>
      </div>
      <div className="divide-y divide-border/30">
        {iocs.map((ioc, i) => {
          const d = iocDef(ioc.type);
          return (
            <div key={i} className="flex items-start gap-2 px-3 py-2 group">
              <span className={cn("rounded px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide border shrink-0 mt-0.5", d.bg, d.border, d.color)}>
                {d.label}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-[10px] text-slate-400 truncate">{ioc.field}</p>
                <p className="text-xs font-mono text-white break-all leading-relaxed">{ioc.value}</p>
              </div>
              <button
                onClick={() => onRemove(i)}
                className="opacity-0 group-hover:opacity-100 transition-opacity mt-0.5 text-slate-400 hover:text-slate-300"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Interactive Log Event Card ─────────────────────────────────────────────────
// A large raw event shown all at once is a wall the eye glazes over. Reveal the
// fields in batches so the student reads incrementally — investigating pivot by
// pivot rather than skimming — while every already-revealed field stays fully
// IOC-taggable. Only kicks in past this many fields; smaller events show whole.
const RAW_REVEAL_INITIAL = 8;
const RAW_REVEAL_STEP    = 8;

function InteractiveLogEventCard({
  event, iocs, onTag, onUntag,
}: { event: TelemetryEvent; iocs: IocEntry[]; onTag: (entry: IocEntry) => void; onUntag: (value: string) => void; }) {
  const [expanded, setExpanded] = useState(true);
  const [popover, setPopover] = useState<PopoverState | null>(null);
  const [visibleCount, setVisibleCount] = useState(RAW_REVEAL_INITIAL);
  const colors = SOURCE_COLORS[event.source] ?? SOURCE_COLORS.edr;

  const rawEntries = Object.entries(event.raw);
  const progressive = rawEntries.length > RAW_REVEAL_INITIAL + 2; // don't bother for a couple extra
  const shownEntries = progressive ? rawEntries.slice(0, visibleCount) : rawEntries;
  const hiddenCount = rawEntries.length - shownEntries.length;

  const taggedValues = new Set(iocs.map(i => i.value));

  function handleValueClick(field: string, value: string, el: HTMLElement) {
    const strVal = String(value);
    if (taggedValues.has(strVal)) {
      onUntag(strVal);
      return;
    }
    const rect = el.getBoundingClientRect();
    setPopover({ field, value: strVal, rect });
  }

  return (
    <>
      <div className={cn("rounded-lg border bg-[#080d14] overflow-hidden", colors.border)}>
        {/* Header */}
        <div className={cn("flex items-center gap-2 px-4 py-2.5 border-b", colors.border, colors.bg)}>
          <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider border", colors.border, colors.bg, colors.text)}>
            {colors.label}
          </span>
          <span className="text-xs font-semibold text-white">{event.event_type}</span>
          <span className="text-xs text-slate-400">{event.hostname}</span>
          <span className="ml-auto text-[10px] font-mono text-slate-400">{event.ts}</span>
        </div>

        {/* Hint bar */}
        <div className="flex items-center gap-2 px-4 py-1.5 bg-cyber-500/5 border-b border-cyber-500/10">
          <Tag className="h-3 w-3 text-cyber-400" />
          <p className="text-[11px] text-cyber-400">Click any value to tag it as an IOC indicator</p>
        </div>

        {/* Raw fields */}
        <div>
          <button
            onClick={() => setExpanded(v => !v)}
            className="flex w-full items-center gap-2 px-4 py-2 text-[11px] text-slate-400 hover:text-slate-200 hover:bg-bg-elevated/40 transition-colors"
          >
            <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", expanded && "rotate-180")} />
            Raw Fields
            <span className="ml-auto text-[10px] text-slate-400">
              {progressive ? `${shownEntries.length} of ${rawEntries.length}` : rawEntries.length} fields
            </span>
          </button>
          {expanded && (
            <div className="px-4 pb-4 pt-1 font-mono text-[11px] space-y-0.5 max-h-80 overflow-y-auto">
              {shownEntries.map(([k, v]) => {
                const strVal = String(v);
                const isTagged = taggedValues.has(strVal);
                const taggedIoc = isTagged ? iocs.find(i => i.value === strVal) : undefined;
                const def = taggedIoc ? iocDef(taggedIoc.type) : null;
                return (
                  <div key={k} className="flex gap-3 leading-relaxed items-center">
                    <span className="text-cyber-300 shrink-0 min-w-[18rem]">{k}</span>
                    <button
                      onClick={e => handleValueClick(k, strVal, e.currentTarget)}
                      className={cn(
                        "text-left break-all rounded px-1 -mx-1 transition-all",
                        isTagged
                          ? cn("font-medium border", def?.bg, def?.border, def?.color)
                          : "text-slate-300 hover:bg-cyber-500/10 hover:text-white cursor-pointer",
                      )}
                    >
                      {strVal}
                      {isTagged && taggedIoc && (
                        <span className="ml-1.5 text-[9px] uppercase tracking-wide opacity-70">
                          [{taggedIoc.type}]
                        </span>
                      )}
                    </button>
                  </div>
                );
              })}
              {progressive && hiddenCount > 0 && (
                <button
                  onClick={() => setVisibleCount(c => c + RAW_REVEAL_STEP)}
                  className="mt-2 flex items-center gap-1.5 rounded border border-cyber-500/30 bg-cyber-500/5 px-2.5 py-1.5 text-[11px] text-cyber-300 hover:bg-cyber-500/10 transition-colors"
                >
                  <ChevronDown className="h-3.5 w-3.5" />
                  Reveal {Math.min(RAW_REVEAL_STEP, hiddenCount)} more field{hiddenCount === 1 ? "" : "s"} ({hiddenCount} hidden)
                </button>
              )}
              {progressive && hiddenCount === 0 && rawEntries.length > RAW_REVEAL_INITIAL && (
                <button
                  onClick={() => setVisibleCount(RAW_REVEAL_INITIAL)}
                  className="mt-2 text-[10px] text-slate-500 hover:text-slate-300 transition-colors"
                >
                  Collapse fields
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {popover && (
        <IocTagPopover
          state={popover}
          onTag={type => {
            onTag({ field: popover.field, value: popover.value, type });
            setPopover(null);
          }}
          onClose={() => setPopover(null)}
        />
      )}
    </>
  );
}

// ─── MCQ Option Button ──────────────────────────────────────────────────────────
interface OptionProps {
  label: string; index: number; selected: boolean; revealed: boolean; correctIndex: number; onSelect: () => void;
}
function OptionButton({ label, index, selected, revealed, correctIndex, onSelect }: OptionProps) {
  const isCorrect = index === correctIndex;
  const letter = String.fromCharCode(65 + index);
  const classes = cn(
    "w-full rounded-lg border px-4 py-3 text-left text-sm transition-all",
    revealed
      ? isCorrect
        ? "border-neon-green/60 bg-neon-green/10 text-neon-green"
        : selected
          ? "border-severity-high/50 bg-severity-high/10 text-severity-high"
          : "border-border/40 bg-bg-elevated/30 text-slate-400"
      : selected
        ? "border-cyber-500/60 bg-cyber-500/10 text-white"
        : "border-border/50 bg-bg-elevated/40 text-slate-300 hover:border-cyber-500/40 hover:bg-cyber-500/5 hover:text-white cursor-pointer",
  );
  return (
    <button onClick={revealed ? undefined : onSelect} className={classes} disabled={revealed}>
      <span className="font-mono font-bold text-xs mr-2 opacity-60">{letter}.</span>
      {label}
    </button>
  );
}

// ─── Inline markdown renderer ────────────────────────────────────────────────────
function renderInline(text: string): React.ReactNode[] {
  const parts = text.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i} className="text-white font-semibold">{part.slice(2, -2)}</strong>;
    }
    return <React.Fragment key={i}>{part}</React.Fragment>;
  });
}

function RichContent({ content }: { content: string }) {
  const blocks = content.split(/\n\n+/);
  return (
    <div className="space-y-5">
      {blocks.map((block, i) => {
        const trimmed = block.trim();
        // Horizontal rule: a line of --- / *** / ___ (markdown authors use it as
        // a section divider). Without this it printed literally as "---".
        if (/^([-*_])\1{2,}$/.test(trimmed)) {
          return <hr key={i} className="border-cyber-500/15" />;
        }
        // ATX heading: #, ##, ### … on its own line. Previously unhandled, so a
        // "## Heading" fell through to the paragraph branch and showed the raw
        // "##". Render it as a styled heading, sized by level.
        const atx = /^(#{1,6})\s+(.+)$/.exec(trimmed);
        if (atx && !trimmed.includes("\n")) {
          const level = atx[1].length;
          const size = level <= 1 ? "text-2xl" : level === 2 ? "text-lg" : "text-base";
          return (
            <h3 key={i} className={cn(size, "font-bold text-cyber-300 mt-6 first:mt-0 border-b border-cyber-500/20 pb-2")}>
              {renderInline(atx[2])}
            </h3>
          );
        }
        if (/^\*\*[^*]+\*\*$/.test(trimmed)) {
          return (
            <h3 key={i} className="text-lg font-bold text-cyber-300 mt-6 first:mt-0 border-b border-cyber-500/20 pb-2">
              {trimmed.slice(2, -2)}
            </h3>
          );
        }
        if (/^[-•] /m.test(trimmed)) {
          const items = trimmed.split(/\n/).filter(Boolean);
          return (
            <ul key={i} className="space-y-2 pl-1">
              {items.map((item, j) => (
                <li key={j} className="flex gap-3 text-base text-slate-300 leading-relaxed">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-cyber-400" />
                  <span>{renderInline(item.replace(/^[-•]\s*/, ""))}</span>
                </li>
              ))}
            </ul>
          );
        }
        return (
          <p key={i} className="text-base text-slate-300 leading-relaxed">
            {renderInline(trimmed)}
          </p>
        );
      })}
    </div>
  );
}

// ─── Reading Task ───────────────────────────────────────────────────────────────
/** Default symbolic engagement XP for a reading task (see ReadingTask.xp). */
const READING_XP_DEFAULT = 5;

/**
 * Reading player with a light "actually read it" gate and an optional inline
 * comprehension checkpoint. The gate opens as soon as the student scrolls the
 * content's end into view OR a short dwell time passes (whichever first) — it
 * is a nudge, not a wall. If the task carries a `checkpoint`, answering it
 * correctly is required to complete (ungraded — pure active recall). Reading
 * still reports 0 to the room score; the engagement XP is awarded separately by
 * RoomClient so it never touches the pass gate.
 */
function ReadingPlayer({ roomId, task, onComplete, isCompleted }: { roomId: string; task: ReadingTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const endRef = useRef<HTMLDivElement | null>(null);
  const [reachedEnd, setReachedEnd] = useState(false);
  const [dwellDone,  setDwellDone]  = useState(false);
  // Checkpoint state — the answer/explanation only exist once the server reveals
  // them (any genuine attempt reveals, per grading.ts's "reading" case).
  const [cpChoice, setCpChoice]     = useState<number | null>(null);
  const [cpCorrect, setCpCorrect]   = useState(false);
  const [cpAnswer, setCpAnswer]     = useState<number | null>(null);
  const [cpExplanation, setCpExplanation] = useState<string | undefined>(undefined);
  const [cpBusy, setCpBusy]         = useState(false);

  const xpReward = task.xp ?? READING_XP_DEFAULT;

  // Dwell fallback: scaled loosely by content length, clamped 5–18s, so a long
  // wall of text can't be dismissed in one blind click but a short note doesn't
  // stall the reader. Skipped entirely once already completed.
  useEffect(() => {
    if (isCompleted) { setReachedEnd(true); setDwellDone(true); return; }
    const words = task.content.split(/\s+/).length;
    const ms = Math.min(18000, Math.max(5000, Math.round((words / 3.5) * 1000)));
    const t = setTimeout(() => setDwellDone(true), ms);
    return () => clearTimeout(t);
  }, [task.id, task.content, isCompleted]);

  // Scroll gate: fire as soon as the end-of-content sentinel is seen.
  useEffect(() => {
    if (isCompleted) return;
    const el = endRef.current;
    if (!el || typeof IntersectionObserver === "undefined") { setReachedEnd(true); return; }
    const obs = new IntersectionObserver(
      entries => { if (entries.some(e => e.isIntersecting)) setReachedEnd(true); },
      { rootMargin: "0px 0px -20% 0px" },
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, [task.id, isCompleted]);

  const cp = task.checkpoint;
  const gateOpen  = reachedEnd || dwellDone;
  const canFinish = gateOpen && (!cp || cpCorrect);

  return (
    <div className="space-y-7">
      <h2 className="text-3xl font-bold text-white leading-tight">{task.heading}</h2>
      <RichContent content={task.content} />
      {task.diagram && <MermaidDiagram chart={task.diagram} caption={task.diagramCaption} />}
      {task.image && <LessonFigure image={task.image} />}
      {task.codeExample && (
        <div className="rounded-lg border border-border bg-[#080d14] overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-bg-elevated/40">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Example</span>
          </div>
          <pre className="px-4 py-4 font-mono text-sm text-cyber-300 overflow-x-auto leading-relaxed whitespace-pre-wrap">
            {task.codeExample}
          </pre>
        </div>
      )}

      {/* End-of-content sentinel for the scroll gate */}
      <div ref={endRef} aria-hidden className="h-px w-full" />

      {/* Inline comprehension checkpoint (ungraded active recall) */}
      {cp && !isCompleted && (
        <div className="rounded-lg border border-cyber-500/25 bg-cyber-500/5 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-cyber-300 shrink-0" />
            <p className="text-sm font-semibold text-white">Quick check</p>
            <span className="text-[10px] text-slate-400">— confirms you read it, not graded</span>
          </div>
          <p className="text-sm text-slate-200">{cp.question}</p>
          <div className="space-y-2">
            {cp.options.map((opt, i) => {
              const chosen = cpChoice === i;
              const isRight = cpAnswer !== null && i === cpAnswer;
              const show = cpChoice !== null && cpAnswer !== null;
              return (
                <button
                  key={i}
                  disabled={cpCorrect || cpBusy}
                  onClick={async () => {
                    setCpChoice(i);
                    setCpBusy(true);
                    try {
                      const result = await submitTask(roomId, task.id, { selectedIndex: i });
                      setCpAnswer(typeof result.reveal.answer === "number" ? result.reveal.answer : null);
                      setCpExplanation(typeof result.reveal.explanation === "string" ? result.reveal.explanation : undefined);
                      if (result.correct) setCpCorrect(true);
                    } finally {
                      setCpBusy(false);
                    }
                  }}
                  className={cn(
                    "w-full text-left rounded border px-3 py-2 text-sm transition",
                    !show && "border-border/60 bg-[#080d14] text-slate-300 hover:border-cyber-500/50",
                    show && isRight && "border-neon-green/50 bg-neon-green/10 text-neon-green",
                    show && chosen && !isRight && "border-severity-critical/50 bg-severity-critical/10 text-severity-critical",
                    show && !chosen && !isRight && "border-border/40 bg-[#080d14] text-slate-500",
                  )}
                >
                  {opt}
                </button>
              );
            })}
          </div>
          {cpChoice !== null && !cpCorrect && !cpBusy && (
            <p className="text-[11px] text-neon-amber">Not quite — re-read the section above and try again.</p>
          )}
          {cpCorrect && cpExplanation && (
            <p className="text-[11px] text-slate-300 leading-relaxed">{cpExplanation}</p>
          )}
        </div>
      )}

      {!isCompleted && (
        <div className="flex items-center gap-3">
          <Button onClick={() => onComplete(0)} variant="primary" size="md" disabled={!canFinish}>
            <CheckCircle2 className="h-4 w-4" />
            Mark as Read
          </Button>
          {!gateOpen && <span className="text-[11px] text-slate-500">Keep reading…</span>}
          {gateOpen && cp && !cpCorrect && <span className="text-[11px] text-slate-500">Answer the quick check to continue</span>}
          {canFinish && <span className="text-[11px] text-neon-green font-medium">+{xpReward} XP</span>}
        </div>
      )}
      {isCompleted && (
        <div className="flex items-center gap-4">
          <div className="inline-flex items-center gap-2 text-sm text-neon-green font-medium">
            <CheckCircle2 className="h-4 w-4" />
            Read
          </div>
          <Button variant="primary" size="md" onClick={() => onComplete(0)}>
            Next Task
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      )}
    </div>
  );
}

// ─── Question Task ──────────────────────────────────────────────────────────────
function QuestionPlayer({ roomId, task, onComplete, isCompleted }: { roomId: string; task: QuestionTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [selected, setSelected]   = useState<number | null>(null);
  const [revealed, setReveal]     = useState(isCompleted);
  const [confirmed, setConfirmed] = useState(isCompleted);
  // One forgiving second chance: a wrong first answer does NOT reveal the correct
  // option — the student gets a nudge and one more try for half credit. Two tries
  // only (options are few, so unlimited retries would be brute-forceable).
  const [wrongOnce, setWrongOnce] = useState(false);
  const [busy, setBusy]           = useState(false);
  const [correct, setCorrect]     = useState(false);
  const [awardedXp, setAwardedXp] = useState(0);
  const [answerIndex, setAnswerIndex] = useState<number | null>(null);
  const [explanation, setExplanation] = useState("");

  if (isCompleted) {
    return (
      <div className="space-y-4">
        <p className="text-xl font-semibold text-white">{task.question}</p>
        <div className="inline-flex items-center gap-2 rounded border border-neon-green/40 bg-neon-green/10 px-3 py-1.5 text-sm text-neon-green">
          <CheckCircle2 className="h-4 w-4" />
          Already completed — +{task.xp} XP earned
        </div>
        <Button variant="primary" size="md" onClick={() => onComplete(0)}>
          Next Task
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  async function handleConfirm() {
    if (selected === null) return;
    setBusy(true);
    try {
      const result = await submitTask(roomId, task.id, { selectedIndex: selected, attemptNumber: wrongOnce ? 2 : 1 });
      if (result.correct) {
        setCorrect(true);
        setAwardedXp(result.xpEarned);
        setAnswerIndex(typeof result.reveal.answer === "number" ? result.reveal.answer : selected);
        setExplanation(typeof result.reveal.explanation === "string" ? result.reveal.explanation : "");
        setReveal(true); setConfirmed(true);          // correct → award (full or half)
      } else if (!wrongOnce) {
        setWrongOnce(true); setSelected(null);        // first miss → nudge + one more try, no reveal
      } else {
        setAwardedXp(0);
        setAnswerIndex(typeof result.reveal.answer === "number" ? result.reveal.answer : null);
        setExplanation(typeof result.reveal.explanation === "string" ? result.reveal.explanation : "");
        setReveal(true); setConfirmed(true);          // second miss → reveal + 0 XP
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      <p className="text-slate-200 leading-relaxed text-base">{task.question}</p>
      <div className="space-y-2">
        {task.options.map((opt, idx) => (
          <OptionButton
            key={idx} label={opt} index={idx}
            selected={selected === idx} revealed={revealed} correctIndex={answerIndex ?? -1}
            onSelect={() => !revealed && setSelected(idx)}
          />
        ))}
      </div>
      {/* First wrong answer: a nudge, not the answer — one more try for half credit. */}
      {wrongOnce && !confirmed && (
        <div className="rounded-lg border border-neon-amber/40 bg-neon-amber/10 p-3 text-sm text-neon-amber">
          Not quite — take another look. One more try, worth half credit.
        </div>
      )}
      {!confirmed && (
        <Button variant="primary" size="md" disabled={selected === null || busy} onClick={handleConfirm}>
          {wrongOnce ? "Try Again" : "Confirm Answer"}
        </Button>
      )}
      {revealed && (
        <div className={cn("rounded-lg border p-4 text-sm",
          correct ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-severity-high/40 bg-severity-high/10 text-severity-high",
        )}>
          <p className="font-semibold mb-1">{correct ? `Correct! +${awardedXp} XP` : "Incorrect"}</p>
          <p className="text-slate-300">{explanation}</p>
        </div>
      )}
      {revealed && (
        <Button variant={correct ? "primary" : "secondary"} size="md" onClick={() => onComplete(correct ? awardedXp : 0)}>
          Next <ChevronRight className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

// ─── Log Analysis Task ──────────────────────────────────────────────────────────
function LogAnalysisPlayer({ roomId, task, onComplete, isCompleted }: { roomId: string; task: LogAnalysisTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [iocs, setIocs]           = useState<IocEntry[]>([]);
  const [answers, setAnswers]     = useState<(number | null)[]>(Array(task.questions.length).fill(null));
  const [revealed, setRevealed]   = useState<boolean[]>(Array(task.questions.length).fill(false));
  const [confirmed, setConfirmed] = useState<boolean[]>(Array(task.questions.length).fill(false));
  const [busy, setBusy]           = useState<boolean[]>(Array(task.questions.length).fill(false));
  const [totalXp, setTotalXp]     = useState(0);
  const [results, setResults]     = useState<Record<number, { correct: boolean; answer: number; explanation: string }>>({});

  const addIoc = useCallback((entry: IocEntry) => {
    setIocs(prev => prev.some(i => i.value === entry.value) ? prev : [...prev, entry]);
  }, []);

  const removeIocByValue = useCallback((value: string) => {
    setIocs(prev => prev.filter(i => i.value !== value));
  }, []);

  const removeIocByIndex = useCallback((idx: number) => {
    setIocs(prev => prev.filter((_, i) => i !== idx));
  }, []);

  if (isCompleted) {
    return (
      <div className="space-y-4">
        <h2 className="text-xl font-bold text-white">{task.heading}</h2>
        <div className="inline-flex items-center gap-2 rounded border border-neon-green/40 bg-neon-green/10 px-3 py-1.5 text-sm text-neon-green">
          <CheckCircle2 className="h-4 w-4" />
          Already completed
        </div>
        <Button variant="primary" size="md" onClick={() => onComplete(0)}>
          Next Task
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  const allRevealed = revealed.every(Boolean);

  async function confirmAnswer(i: number) {
    const selected = answers[i];
    // Guard against double-submit: a second click while the first request is
    // in flight would grade (and award XP for) the same question twice — this
    // XP is server-authoritative, so it inflates profiles.xp, not just the UI.
    if (selected === null || confirmed[i] || busy[i]) return;
    setBusy(prev => prev.map((v, idx) => idx === i ? true : v));
    try {
      const result = await submitTask(roomId, task.id, { questionIndex: i, selectedIndex: selected });
      setResults(prev => ({
        ...prev,
        [i]: {
          correct: result.correct,
          answer: typeof result.reveal.answer === "number" ? result.reveal.answer : selected,
          explanation: typeof result.reveal.explanation === "string" ? result.reveal.explanation : "",
        },
      }));
      setRevealed(prev  => prev.map((v, idx) => idx === i ? true : v));
      setConfirmed(prev => prev.map((v, idx) => idx === i ? true : v));
      setTotalXp(prev => prev + result.xpEarned);
    } finally {
      setBusy(prev => prev.map((v, idx) => idx === i ? false : v));
    }
  }

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold text-white">{task.heading}</h2>
      <p className="text-sm italic text-slate-400 border-l-2 border-cyber-500/40 pl-3">{task.context}</p>

      <InteractiveLogEventCard
        event={task.event}
        iocs={iocs}
        onTag={addIoc}
        onUntag={removeIocByValue}
      />

      <IocNotebook iocs={iocs} onRemove={removeIocByIndex} />

      <div className="space-y-8">
        {task.questions.map((q, i) => {
          const result = results[i];
          const isCorrect = !!result?.correct;
          return (
            <div key={i} className="space-y-3">
              <p className="text-sm font-semibold text-white">
                <span className="text-slate-400 mr-2">Q{i + 1}.</span>
                {q.question}
              </p>

              {iocs.length > 0 && (
                <div className="flex flex-wrap gap-1.5 py-1">
                  {iocs.slice(0, 4).map((ioc, j) => {
                    const d = iocDef(ioc.type);
                    return (
                      <span key={j} className={cn("rounded px-1.5 py-0.5 text-[10px] font-mono border", d.bg, d.border, d.color)}>
                        {ioc.value.length > 35 ? ioc.value.slice(0, 35) + "…" : ioc.value}
                      </span>
                    );
                  })}
                  {iocs.length > 4 && (
                    <span className="text-[10px] text-slate-400 self-center">+{iocs.length - 4} more in notebook</span>
                  )}
                </div>
              )}

              <div className="space-y-2">
                {q.options.map((opt, idx) => (
                  <OptionButton
                    key={idx} label={opt} index={idx}
                    selected={answers[i] === idx} revealed={revealed[i]} correctIndex={result?.answer ?? -1}
                    onSelect={() => !revealed[i] && setAnswers(prev => prev.map((v, j) => j === i ? idx : v))}
                  />
                ))}
              </div>
              {!confirmed[i] && (
                <Button variant="secondary" size="sm" disabled={answers[i] === null || busy[i]}
                  onClick={() => confirmAnswer(i)}>
                  Confirm
                </Button>
              )}
              {revealed[i] && result && (
                <div className={cn("rounded-lg border p-3 text-sm",
                  isCorrect ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-severity-high/40 bg-severity-high/10 text-severity-high",
                )}>
                  <p className="font-semibold mb-1">{isCorrect ? `Correct! +${q.xp} XP` : "Incorrect"}</p>
                  <p className="text-slate-300">{result.explanation}</p>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {allRevealed && (
        <>
          {iocs.length > 0 && (
            <div className="rounded-lg border border-cyber-500/20 bg-cyber-500/5 px-4 py-3">
              <p className="text-xs font-semibold text-cyber-300 mb-1">
                You collected {iocs.length} IOC{iocs.length !== 1 ? "s" : ""} during this investigation
              </p>
              <p className="text-xs text-slate-400">
                Great work! Real analysts document indicators exactly like this — they go into threat intel platforms to block future attacks.
              </p>
            </div>
          )}
          <Button variant="primary" size="md" onClick={() => onComplete(totalXp)}>
            Next <ChevronRight className="h-4 w-4" />
          </Button>
        </>
      )}
    </div>
  );
}

// ─── Flag Task ──────────────────────────────────────────────────────────────────
function FlagPlayer({ roomId, task, onComplete, isCompleted, prevLogEvent }: { roomId: string; task: FlagTask; onComplete: (xp: number) => void; isCompleted: boolean; prevLogEvent?: TelemetryEvent }) {
  const [input, setInput]       = useState("");
  const [status, setStatus]     = useState<"idle" | "correct" | "wrong" | "checking">("idle");
  const [showHint, setShowHint] = useState(false);
  const [awardedXp, setAwardedXp] = useState(task.xp);

  if (isCompleted) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Flag className="h-5 w-5 text-cyber-300" />
          <p className="text-slate-200 leading-relaxed">{task.prompt.split("\n")[0]}</p>
        </div>
        {prevLogEvent && <ReadOnlyEventCard event={prevLogEvent} />}
        <div className="inline-flex items-center gap-2 rounded border border-neon-green/40 bg-neon-green/10 px-3 py-1.5 text-sm text-neon-green">
          <CheckCircle2 className="h-4 w-4" />
          Already completed — +{task.xp} XP earned
        </div>
        <Button variant="primary" size="md" onClick={() => onComplete(0)}>
          Next Task
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  async function submit() {
    setStatus("checking");
    const result = await submitTask(roomId, task.id, { value: input });
    if (result.correct) {
      setAwardedXp(result.xpEarned);
      setStatus("correct");
    } else {
      setStatus("wrong");
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2 mb-1">
        <Flag className="h-5 w-5 text-cyber-300" />
        <span className="text-xs font-semibold uppercase tracking-wider text-cyber-300">Flag Challenge</span>
      </div>

      {prevLogEvent && <ReadOnlyEventCard event={prevLogEvent} />}

      <p className="text-slate-200 leading-relaxed whitespace-pre-line">{task.prompt}</p>

      {task.hint && (
        <div>
          <button
            onClick={() => setShowHint(v => !v)}
            className="inline-flex items-center gap-1.5 text-xs text-neon-amber hover:text-neon-amber/80 transition-colors"
          >
            <Lightbulb className="h-3.5 w-3.5" />
            {showHint ? "Hide hint" : "Show hint"}
          </button>
          {showHint && (
            <div className="mt-2 rounded border border-neon-amber/30 bg-neon-amber/5 px-3 py-2 text-sm text-neon-amber">
              {task.hint}
            </div>
          )}
        </div>
      )}

      {status !== "correct" && (
        <div className="flex gap-3">
          <input
            type="text" value={input}
            onChange={e => { setInput(e.target.value); setStatus("idle"); }}
            onKeyDown={e => e.key === "Enter" && submit()}
            placeholder="Enter your answer…"
            className={cn(
              "h-10 flex-1 rounded-md border bg-[#080d14] px-3 font-mono text-sm text-white placeholder-slate-500",
              "focus:outline-none focus:ring-2",
              status === "wrong"
                ? "border-severity-high/50 focus:ring-severity-high/30"
                : "border-cyber-500/40 focus:ring-cyber-500/30 focus:border-cyber-500/60",
            )}
          />
          <Button variant="primary" size="md" onClick={submit} disabled={!input.trim() || status === "checking"}>Submit</Button>
        </div>
      )}

      {status === "wrong" && (
        <div className="rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high">
          Incorrect — try again
        </div>
      )}
      {status === "correct" && (
        <>
          <div className="rounded-lg border border-neon-green/40 bg-neon-green/10 px-4 py-3 text-sm text-neon-green font-semibold">
            Correct! +{awardedXp} XP
          </div>
          <Button variant="primary" size="md" onClick={() => onComplete(awardedXp)}>
            Next <ChevronRight className="h-4 w-4" />
          </Button>
        </>
      )}
    </div>
  );
}

// ─── Read-Only Event Card (used by AnalystChoicePlayer) ─────────────────────────
function ReadOnlyEventCard({ event }: { event: TelemetryEvent }) {
  const [expanded, setExpanded] = useState(true);
  const colors = SOURCE_COLORS[event.source] ?? SOURCE_COLORS.edr;
  return (
    <div className={cn("rounded-lg border bg-[#080d14] overflow-hidden", colors.border)}>
      <div className={cn("flex items-center gap-2 px-4 py-2.5 border-b", colors.border, colors.bg)}>
        <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider border", colors.border, colors.bg, colors.text)}>
          {colors.label}
        </span>
        <span className="text-xs font-semibold text-white">{event.event_type}</span>
        <span className="text-xs text-slate-400">{event.hostname}</span>
        <span className="ml-auto text-[10px] font-mono text-slate-400">{event.ts}</span>
      </div>
      <div>
        <button
          onClick={() => setExpanded(v => !v)}
          className="flex w-full items-center gap-2 px-4 py-2 text-[11px] text-slate-400 hover:text-slate-200 hover:bg-bg-elevated/40 transition-colors"
        >
          <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", expanded && "rotate-180")} />
          Raw Fields
          <span className="ml-auto text-[10px] text-slate-400">{Object.keys(event.raw).length} fields</span>
        </button>
        {expanded && (
          <div className="px-4 pb-4 pt-1 font-mono text-[11px] space-y-0.5 max-h-80 overflow-y-auto">
            {Object.entries(event.raw).map(([k, v]) => (
              <div key={k} className="flex gap-3 leading-relaxed">
                <span className="text-cyber-300 shrink-0 min-w-[18rem]">{k}</span>
                <span className="text-slate-300 break-all">{String(v)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Analyst Choice Task ─────────────────────────────────────────────────────────
function AnalystChoicePlayer({ roomId, task, onComplete, isCompleted }: { roomId: string; task: AnalystChoiceTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  // One forgiving second chance at half credit; a wrong first verdict does not
  // reveal the correct one (only 4 verdicts, so unlimited retries would be trivial).
  const [wrongOnce, setWrongOnce] = useState(false);
  const [busy, setBusy] = useState(false);
  const [awardedXp, setAwardedXp] = useState(0);
  const [correctVerdict, setCorrectVerdict] = useState<string | null>(null);
  const [explanation, setExplanation] = useState("");
  const [fpTrap, setFpTrap] = useState<string | undefined>(undefined);
  const [resultCorrect, setResultCorrect] = useState(false);

  async function handleSubmit() {
    if (!selected) return;
    setBusy(true);
    try {
      const result = await submitTask(roomId, task.id, { verdict: selected, attemptNumber: wrongOnce ? 2 : 1 });
      if (result.correct) {
        setAwardedXp(result.xpEarned);
        setResultCorrect(true);
        setCorrectVerdict(typeof result.reveal.correct_verdict === "string" ? result.reveal.correct_verdict : selected);
        setExplanation(typeof result.reveal.explanation === "string" ? result.reveal.explanation : "");
        setFpTrap(typeof result.reveal.fp_trap === "string" ? result.reveal.fp_trap : undefined);
        setRevealed(true);
      } else if (!wrongOnce) {
        setWrongOnce(true); setSelected(null);
      } else {
        setAwardedXp(0);
        setResultCorrect(false);
        setCorrectVerdict(typeof result.reveal.correct_verdict === "string" ? result.reveal.correct_verdict : null);
        setExplanation(typeof result.reveal.explanation === "string" ? result.reveal.explanation : "");
        setFpTrap(typeof result.reveal.fp_trap === "string" ? result.reveal.fp_trap : undefined);
        setRevealed(true);
      }
    } finally {
      setBusy(false);
    }
  }

  const VERDICTS = [
    { key: "true_positive",  label: "True Positive",   desc: "Real threat — take action now",   activeClass: "border-red-500/70 bg-red-500/15 text-red-300"          },
    { key: "false_positive", label: "False Positive",  desc: "Benign — close this alert",       activeClass: "border-neon-green/70 bg-neon-green/15 text-neon-green"  },
    { key: "escalate",       label: "Escalate to T2",  desc: "Needs senior analyst review",     activeClass: "border-neon-amber/70 bg-neon-amber/15 text-neon-amber"  },
    { key: "informational",  label: "Informational",   desc: "Log and monitor — no action",     activeClass: "border-slate-500/70 bg-slate-500/15 text-slate-300"     },
  ] as const;

  const isCorrect = resultCorrect;

  if (isCompleted) {
    return (
      <div className="space-y-4">
        <h2 className="text-xl font-bold text-white">{task.heading}</h2>
        <div className="inline-flex items-center gap-2 rounded border border-neon-green/40 bg-neon-green/10 px-3 py-1.5 text-sm text-neon-green">
          <CheckCircle2 className="h-4 w-4" />
          Already completed — +{task.xp} XP earned
        </div>
        <Button variant="primary" size="md" onClick={() => onComplete(0)}>
          Next Task <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold text-white">{task.heading}</h2>

      <div className="rounded-lg border border-cyber-500/20 bg-cyber-500/5 px-4 py-3">
        <p className="text-[11px] uppercase tracking-wider text-cyber-400 font-semibold mb-1">Scenario</p>
        <p className="text-sm text-slate-300 leading-relaxed">{task.scenario}</p>
      </div>

      <ReadOnlyEventCard event={task.event} />

      <div className="space-y-3">
        <p className="text-sm font-semibold text-slate-200">What is your verdict on this alert?</p>
        <div className="grid grid-cols-2 gap-3">
          {VERDICTS.map(v => (
            <button
              key={v.key}
              onClick={() => !revealed && setSelected(v.key)}
              disabled={revealed}
              className={cn(
                "rounded-lg border px-4 py-3 text-left transition-all",
                revealed
                  ? v.key === correctVerdict
                    ? "border-neon-green/60 bg-neon-green/10 text-neon-green cursor-default"
                    : selected === v.key && !isCorrect
                      ? "border-severity-high/50 bg-severity-high/10 text-severity-high cursor-default"
                      : "border-border/30 bg-bg-elevated/20 text-slate-400 cursor-default"
                  : selected === v.key
                    ? v.activeClass
                    : "border-border/50 bg-bg-elevated/40 text-slate-400 hover:border-border/70 hover:text-slate-200 cursor-pointer",
              )}
            >
              <p className="font-semibold text-sm">{v.label}</p>
              <p className="text-xs opacity-70 mt-0.5">{v.desc}</p>
            </button>
          ))}
        </div>
      </div>

      {/* First wrong verdict: a nudge, not the answer — one more try for half credit. */}
      {wrongOnce && !revealed && (
        <div className="rounded-lg border border-neon-amber/40 bg-neon-amber/10 p-3 text-sm text-neon-amber">
          Not quite — reconsider what the evidence actually supports. One more try, worth half credit.
        </div>
      )}

      {!revealed && (
        <Button variant="primary" size="md" disabled={!selected || busy} onClick={handleSubmit}>
          {wrongOnce ? "Try Again" : "Submit Verdict"}
        </Button>
      )}

      {revealed && (
        <div className={cn("rounded-lg border p-4 text-sm space-y-2",
          isCorrect ? "border-neon-green/40 bg-neon-green/10" : "border-severity-high/40 bg-severity-high/10",
        )}>
          <p className={cn("font-semibold", isCorrect ? "text-neon-green" : "text-severity-high")}>
            {isCorrect ? `Correct! +${awardedXp} XP` : "Incorrect — review the reasoning below"}
          </p>
          <p className="text-slate-300">{explanation}</p>
          {fpTrap && !isCorrect && (
            <div className="mt-2 border-l-2 border-neon-amber/40 pl-3">
              <p className="text-[11px] uppercase tracking-wider text-neon-amber font-semibold mb-0.5">Common trap</p>
              <p className="text-xs text-neon-amber/80">{fpTrap}</p>
            </div>
          )}
        </div>
      )}

      {revealed && (
        <Button variant={isCorrect ? "primary" : "secondary"} size="md" onClick={() => onComplete(isCorrect ? awardedXp : 0)}>
          Next <ChevronRight className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

// ─── Matching Task ────────────────────────────────────────────────────────────────
function MatchingPlayer({ roomId, task, onComplete, isCompleted }: { roomId: string; task: MatchingTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [selectedLeft, setSelectedLeft] = useState<string | null>(null);
  // { leftId -> right TEXT }. The right side has no id: the server delivers it
  // as bare shuffled strings precisely so no id can tie a right item back to
  // its left one. Text is the key — verified unique across every matching task.
  const [connections, setConnections] = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [awardedXp, setAwardedXp] = useState(0);
  const [result, setResult] = useState<{
    correctCount: number;
    total: number;
    perPair: { id: string; correct: boolean }[];
    solution: { id: string; left: string; right: string }[];
    explanation: string;
  } | null>(null);

  const allConnected = Object.keys(connections).length === task.left.length;
  const allCorrect = !!result && result.correctCount === result.total;
  const correctOf = (leftId: string) => result?.perPair.find(p => p.id === leftId)?.correct;

  function handleLeftClick(leftId: string) {
    if (revealed) return;
    setSelectedLeft(prev => prev === leftId ? null : leftId);
  }

  function handleRightClick(rightText: string) {
    if (revealed || !selectedLeft) return;
    setConnections(prev => ({ ...prev, [selectedLeft]: rightText }));
    setSelectedLeft(null);
  }

  async function checkMatches() {
    setBusy(true);
    try {
      const res = await submitTask(roomId, task.id, { connections });
      setAwardedXp(res.xpEarned);
      setResult({
        correctCount: Number(res.reveal.correctCount ?? 0),
        total: Number(res.reveal.total ?? task.left.length),
        perPair: Array.isArray(res.reveal.perPair) ? res.reveal.perPair : [],
        solution: Array.isArray(res.reveal.solution) ? res.reveal.solution : [],
        explanation: typeof res.reveal.explanation === "string" ? res.reveal.explanation : "",
      });
      setRevealed(true);
    } finally {
      setBusy(false);
    }
  }

  if (isCompleted) {
    return (
      <div className="space-y-4">
        <h2 className="text-xl font-bold text-white">{task.heading}</h2>
        <div className="inline-flex items-center gap-2 rounded border border-neon-green/40 bg-neon-green/10 px-3 py-1.5 text-sm text-neon-green">
          <CheckCircle2 className="h-4 w-4" />
          Already completed — +{task.xp} XP earned
        </div>
        <Button variant="primary" size="md" onClick={() => onComplete(0)}>
          Next Task <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold text-white">{task.heading}</h2>
      <p className="text-sm text-slate-400">{task.instructions}</p>

      <div className="grid grid-cols-2 gap-3">
        {/* Left column */}
        <div className="space-y-2">
          <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">Match from</p>
          {task.left.map(item => {
            const connectedText = connections[item.id];
            const isSelected = selectedLeft === item.id;
            const isCorrect = revealed && correctOf(item.id) === true;
            const isWrong  = revealed && connectedText !== undefined && correctOf(item.id) === false;
            return (
              <button
                key={item.id}
                onClick={() => handleLeftClick(item.id)}
                disabled={revealed}
                className={cn(
                  "w-full rounded-lg border px-3 py-2.5 text-left text-sm transition-all",
                  revealed
                    ? isCorrect ? "border-neon-green/60 bg-neon-green/10 text-neon-green"
                      : isWrong ? "border-severity-high/50 bg-severity-high/10 text-severity-high"
                      : "border-border/40 bg-bg-elevated/30 text-slate-400"
                    : isSelected ? "border-cyber-500/70 bg-cyber-500/15 text-white"
                    : connectedText ? "border-cyber-500/30 bg-cyber-500/5 text-white"
                    : "border-border/50 bg-bg-elevated/40 text-slate-300 hover:border-cyber-500/40 hover:text-white",
                )}
              >
                <span className="font-medium">{item.text}</span>
                {connectedText && !revealed && (
                  <span className="mt-0.5 block text-[10px] text-cyber-400">connected</span>
                )}
              </button>
            );
          })}
        </div>

        {/* Right column */}
        <div className="space-y-2">
          <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
            {selectedLeft ? "Click to connect" : "Select left first"}
          </p>
          {/* Already shuffled server-side — do NOT reorder here. */}
          {task.right.map(rightText => {
            const connectedLeftId = Object.entries(connections).find(([, txt]) => txt === rightText)?.[0];
            const isConnected = !!connectedLeftId;
            const isCorrect = revealed && connectedLeftId !== undefined && correctOf(connectedLeftId) === true;
            const isWrong  = revealed && connectedLeftId !== undefined && correctOf(connectedLeftId) === false;
            return (
              <button
                key={rightText}
                onClick={() => handleRightClick(rightText)}
                disabled={revealed || !selectedLeft}
                className={cn(
                  "w-full rounded-lg border px-3 py-2.5 text-left text-sm transition-all",
                  revealed
                    ? isCorrect ? "border-neon-green/60 bg-neon-green/10 text-neon-green"
                      : isWrong ? "border-severity-high/50 bg-severity-high/10 text-severity-high"
                      : "border-border/40 bg-bg-elevated/30 text-slate-400"
                    : selectedLeft && !isConnected ? "border-cyber-500/40 bg-cyber-500/5 text-slate-200 hover:border-cyber-500/70 hover:text-white cursor-pointer"
                    : isConnected ? "border-cyber-500/30 bg-cyber-500/5 text-white"
                    : "border-border/50 bg-bg-elevated/40 text-slate-300 cursor-default",
                )}
              >
                {rightText}
              </button>
            );
          })}
        </div>
      </div>

      {!revealed && (
        <p className="text-xs text-slate-400">
          {Object.keys(connections).length}/{task.left.length} pairs connected
          {selectedLeft ? " — now click an item on the right" : " — select an item on the left to begin"}
        </p>
      )}

      {!revealed && allConnected && (
        <Button variant="primary" size="md" disabled={busy} onClick={checkMatches}>
          Check Matches
        </Button>
      )}

      {revealed && result && (
        <div className={cn("rounded-lg border p-4 text-sm space-y-2",
          allCorrect ? "border-neon-green/40 bg-neon-green/10" : "border-neon-amber/40 bg-neon-amber/10",
        )}>
          <p className={cn("font-semibold", allCorrect ? "text-neon-green" : "text-neon-amber")}>
            {allCorrect ? `Perfect! +${awardedXp} XP` : `${result.correctCount}/${result.total} correct`}
          </p>
          {/* The correct pairing, released only now that an attempt is in —
              without this a student who got some wrong learns nothing. */}
          {!allCorrect && (
            <ul className="space-y-1 border-l-2 border-neon-amber/40 pl-3">
              {result.solution.map(s => (
                <li key={s.id} className="text-xs text-slate-300">
                  <span className="text-white">{s.left}</span> → {s.right}
                </li>
              ))}
            </ul>
          )}
          <p className="text-slate-300">{result.explanation}</p>
        </div>
      )}

      {revealed && (
        <Button variant={allCorrect ? "primary" : "secondary"} size="md"
          onClick={() => onComplete(awardedXp)}>
          Next <ChevronRight className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

// ─── Ordering Task ────────────────────────────────────────────────────────────────
function OrderingPlayer({ roomId, task, onComplete, isCompleted }: { roomId: string; task: OrderingTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [placed, setPlaced] = useState<(string | null)[]>(Array(task.items.length).fill(null));
  const [selectedItem, setSelectedItem] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [xpEarned, setXpEarned] = useState(0);
  const [result, setResult] = useState<{
    correctCount: number;
    total: number;
    perSlot: { slot: number; correct: boolean }[];
    correctOrder: string[];
    explanation: string;
  } | null>(null);

  // task.items arrives ALREADY shuffled by the server. It must not be reordered
  // here: 29 of 32 ordering tasks are authored with items already in the correct
  // sequence, so the delivered order is the only thing standing between the
  // student and the answer. The old client-side rotation was applied on top of
  // the authored (correct) order, which meant the answer was one trivial
  // un-rotation away in the page payload.
  const poolItems = task.items;

  const allPlaced = placed.every(Boolean);
  const placedSet = new Set(placed.filter(Boolean) as string[]);
  const allCorrect = !!result && result.correctCount === result.total;
  const slotCorrect = (i: number) => result?.perSlot.find(s => s.slot === i)?.correct;

  async function submitOrder() {
    setBusy(true);
    try {
      const res = await submitTask(roomId, task.id, { placed });
      setXpEarned(res.xpEarned);
      setResult({
        correctCount: Number(res.reveal.correctCount ?? 0),
        total: Number(res.reveal.total ?? task.items.length),
        perSlot: Array.isArray(res.reveal.perSlot) ? res.reveal.perSlot : [],
        correctOrder: Array.isArray(res.reveal.correctOrder) ? res.reveal.correctOrder : [],
        explanation: typeof res.reveal.explanation === "string" ? res.reveal.explanation : "",
      });
      setRevealed(true);
    } finally {
      setBusy(false);
    }
  }

  function handleItemClick(itemId: string) {
    if (revealed) return;
    const currentSlot = placed.indexOf(itemId);
    if (currentSlot !== -1) {
      setPlaced(prev => prev.map((v, i) => i === currentSlot ? null : v));
      setSelectedItem(itemId);
    } else {
      setSelectedItem(prev => prev === itemId ? null : itemId);
    }
  }

  function handleSlotClick(slotIndex: number) {
    if (revealed) return;
    if (!selectedItem && placed[slotIndex]) {
      const itemId = placed[slotIndex]!;
      setPlaced(prev => prev.map((v, i) => i === slotIndex ? null : v));
      setSelectedItem(itemId);
    } else if (selectedItem) {
      const prevSlot = placed.indexOf(selectedItem);
      setPlaced(prev => {
        const next = [...prev];
        if (prevSlot !== -1) next[prevSlot] = null;
        next[slotIndex] = selectedItem;
        return next;
      });
      setSelectedItem(null);
    }
  }

  if (isCompleted) {
    return (
      <div className="space-y-4">
        <h2 className="text-xl font-bold text-white">{task.heading}</h2>
        <div className="inline-flex items-center gap-2 rounded border border-neon-green/40 bg-neon-green/10 px-3 py-1.5 text-sm text-neon-green">
          <CheckCircle2 className="h-4 w-4" />
          Already completed — +{task.xp} XP earned
        </div>
        <Button variant="primary" size="md" onClick={() => onComplete(0)}>
          Next Task <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-bold text-white">{task.heading}</h2>
      <p className="text-sm text-slate-400">{task.instructions}</p>

      <div className="grid gap-5 md:grid-cols-2">
        {/* Numbered slots */}
        <div className="space-y-2">
          <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">Correct Order</p>
          {task.items.map((_, slotIdx) => {
            const placedId = placed[slotIdx];
            const placedItem = placedId ? task.items.find(i => i.id === placedId) : null;
            const isCorrect = revealed && slotCorrect(slotIdx) === true;
            const isWrong  = revealed && !!placedId && slotCorrect(slotIdx) === false;
            return (
              <button
                key={slotIdx}
                onClick={() => handleSlotClick(slotIdx)}
                disabled={revealed}
                className={cn(
                  "w-full rounded-lg border px-3 py-2.5 text-left text-sm transition-all flex items-center gap-3",
                  revealed
                    ? isCorrect ? "border-neon-green/60 bg-neon-green/10"
                      : isWrong ? "border-severity-high/50 bg-severity-high/10"
                      : "border-border/40 bg-bg-elevated/20"
                    : selectedItem && !placedId ? "border-cyber-500/60 bg-cyber-500/10 cursor-pointer"
                    : placedItem ? "border-cyber-500/30 bg-cyber-500/5 cursor-pointer"
                    : "border-dashed border-border/40 bg-transparent cursor-default",
                )}
              >
                <span className={cn(
                  "flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-bold",
                  revealed && isCorrect ? "bg-neon-green/20 text-neon-green"
                    : revealed && isWrong ? "bg-severity-high/20 text-severity-high"
                    : "bg-cyber-500/20 text-cyber-300",
                )}>
                  {slotIdx + 1}
                </span>
                <span className={cn(
                  "flex-1 text-sm",
                  revealed && isCorrect ? "text-neon-green"
                    : revealed && isWrong ? "text-severity-high"
                    : placedItem ? "text-white"
                    : "text-slate-400 italic",
                )}>
                  {placedItem ? placedItem.text : "— empty —"}
                </span>
              </button>
            );
          })}
        </div>

        {/* Items pool */}
        <div className="space-y-2">
          <p className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
            {selectedItem ? "Now click a numbered slot" : "Select an item to place"}
          </p>
          {poolItems.map(item => {
            const isPlaced   = placedSet.has(item.id);
            const isSelected = selectedItem === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleItemClick(item.id)}
                disabled={revealed}
                className={cn(
                  "w-full rounded-lg border px-3 py-2.5 text-left text-sm transition-all",
                  isSelected
                    ? "border-cyber-500/80 bg-cyber-500/15 text-white shadow-[0_0_10px_rgba(0,212,255,0.12)]"
                    : isPlaced
                      ? "border-border/20 bg-bg-elevated/20 text-slate-400 cursor-pointer"
                      : "border-border/50 bg-bg-elevated/40 text-slate-300 hover:border-cyber-500/40 hover:text-white cursor-pointer",
                )}
              >
                {item.text}
                {isPlaced && <span className="ml-2 text-[10px] text-slate-400">(placed — click to move)</span>}
              </button>
            );
          })}
        </div>
      </div>

      {!revealed && (
        <p className="text-xs text-slate-400">
          {placed.filter(Boolean).length}/{task.items.length} items placed
          {selectedItem ? " — click a numbered slot on the left" : ""}
        </p>
      )}

      {!revealed && allPlaced && (
        <Button variant="primary" size="md" disabled={busy} onClick={submitOrder}>
          Submit Order
        </Button>
      )}

      {revealed && result && (
        <div className={cn("rounded-lg border p-4 text-sm space-y-2",
          allCorrect ? "border-neon-green/40 bg-neon-green/10" : "border-neon-amber/40 bg-neon-amber/10",
        )}>
          <p className={cn("font-semibold", allCorrect ? "text-neon-green" : "text-neon-amber")}>
            {allCorrect ? `Perfect order! +${xpEarned} XP` : `${result.correctCount}/${result.total} in the correct position`}
          </p>
          {/* Released only after an attempt — otherwise a student who got the
              sequence wrong has nothing to learn from. */}
          {!allCorrect && result.correctOrder.length > 0 && (
            <ol className="space-y-0.5 border-l-2 border-neon-amber/40 pl-3">
              {result.correctOrder.map((id, i) => (
                <li key={id} className="text-xs text-slate-300">
                  <span className="text-slate-500">{i + 1}.</span>{" "}
                  {task.items.find(it => it.id === id)?.text ?? id}
                </li>
              ))}
            </ol>
          )}
          <p className="text-slate-300">{result.explanation}</p>
        </div>
      )}

      {revealed && (
        <Button variant={allCorrect ? "primary" : "secondary"} size="md" onClick={() => onComplete(xpEarned)}>
          Next <ChevronRight className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

// ─── Query Fill Task ──────────────────────────────────────────────────────────
// The one task type where the student WRITES a query fragment instead of only
// reading one in a codeExample or picking a multiple-choice answer about what a
// pre-written query does — closes the platform's one real KQL/SPL practice gap.
const BLANK_TOKEN = /\{\{([a-zA-Z0-9_]+)\}\}/g;

function QueryFillPlayer({ roomId, task, onComplete, isCompleted }: { roomId: string; task: QueryFillTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [values, setValues]     = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState(false);
  const [busy, setBusy]         = useState(false);
  const [blankResults, setBlankResults] = useState<Record<string, { correct: boolean; answers: string[] }>>({});
  const [explanation, setExplanation] = useState("");
  const [xpEarned, setXpEarned] = useState(0);
  const [allCorrect, setAllCorrect] = useState(false);

  // Split the template into alternating text / {{blankId}} segments, keeping
  // the delimiters so we know exactly where each input goes.
  const segments = React.useMemo(() => task.template.split(BLANK_TOKEN), [task.template]);

  const blankIds = task.blanks.map(b => b.id);
  const allFilled = blankIds.every(id => (values[id] ?? "").trim().length > 0);
  const isBlankCorrect = (id: string) => !!blankResults[id]?.correct;
  const correctCount = blankIds.filter(isBlankCorrect).length;

  async function runQuery() {
    setBusy(true);
    try {
      const result = await submitTask(roomId, task.id, { values });
      const blanks = Array.isArray(result.reveal.blanks) ? result.reveal.blanks : [];
      const byId: Record<string, { correct: boolean; answers: string[] }> = {};
      for (const b of blanks) byId[b.id] = { correct: !!b.correct, answers: Array.isArray(b.answers) ? b.answers : [] };
      setBlankResults(byId);
      setExplanation(typeof result.reveal.explanation === "string" ? result.reveal.explanation : "");
      setXpEarned(result.xpEarned);
      setAllCorrect(result.correct);
      setRevealed(true);
    } finally {
      setBusy(false);
    }
  }

  if (isCompleted) {
    return (
      <div className="space-y-4">
        <h2 className="text-xl font-bold text-white">{task.heading}</h2>
        <div className="inline-flex items-center gap-2 rounded border border-neon-green/40 bg-neon-green/10 px-3 py-1.5 text-sm text-neon-green">
          <CheckCircle2 className="h-4 w-4" />
          Already completed — +{task.xp} XP earned
        </div>
        <Button variant="primary" size="md" onClick={() => onComplete(0)}>
          Next Task <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <h2 className="text-xl font-bold text-white">{task.heading}</h2>
        <span className="rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-cyber-300">
          {task.language}
        </span>
      </div>
      <p className="text-sm text-slate-400 leading-relaxed">{task.context}</p>

      <div className="rounded-lg border border-border bg-[#080d14] p-4 font-mono text-sm leading-relaxed text-slate-300 whitespace-pre-wrap">
        {segments.map((seg, i) => {
          // Odd indices are the captured {{id}} groups from the split regex.
          if (i % 2 === 1) {
            const id = seg;
            const blank = task.blanks.find(b => b.id === id);
            const correct = revealed && isBlankCorrect(id);
            const wrong   = revealed && !isBlankCorrect(id);
            return (
              <input
                key={id}
                type="text"
                value={values[id] ?? ""}
                onChange={e => setValues(v => ({ ...v, [id]: e.target.value }))}
                disabled={revealed}
                placeholder={blank?.placeholder ?? "…"}
                size={Math.max(6, (blank?.placeholder?.length ?? 6) + 2)}
                className={cn(
                  "mx-0.5 inline-block rounded border bg-[#0d1520] px-1.5 py-0.5 font-mono text-sm align-baseline",
                  "focus:outline-none focus:ring-2 focus:ring-cyber-500/30",
                  correct ? "border-neon-green/60 text-neon-green"
                    : wrong ? "border-severity-high/60 text-severity-high"
                    : "border-cyber-500/40 text-white",
                )}
              />
            );
          }
          return <span key={i}>{seg}</span>;
        })}
      </div>

      {revealed && !allCorrect && (
        <div className="space-y-1">
          {task.blanks.filter(b => !isBlankCorrect(b.id)).map(b => (
            <p key={b.id} className="text-xs text-severity-high">
              <span className="font-mono">{b.placeholder ?? b.id}</span>: expected <span className="font-mono text-slate-300">{blankResults[b.id]?.answers[0] ?? ""}</span>
            </p>
          ))}
        </div>
      )}

      {!revealed && (
        <Button variant="primary" size="md" disabled={!allFilled || busy} onClick={runQuery}>
          Run Query
        </Button>
      )}

      {revealed && (
        <div className={cn("rounded-lg border p-4 text-sm space-y-2",
          allCorrect ? "border-neon-green/40 bg-neon-green/10" : "border-neon-amber/40 bg-neon-amber/10",
        )}>
          <p className={cn("font-semibold", allCorrect ? "text-neon-green" : "text-neon-amber")}>
            {allCorrect ? `Correct! +${xpEarned} XP` : `${correctCount}/${blankIds.length} blanks correct`}
          </p>
          <p className="text-slate-300">{explanation}</p>
        </div>
      )}

      {revealed && (
        <Button variant={allCorrect ? "primary" : "secondary"} size="md" onClick={() => onComplete(xpEarned)}>
          Next <ChevronRight className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

function WrittenReportPlayer({ roomId, task, onComplete, isCompleted }: { roomId: string; task: WrittenReportTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [text, setText]         = useState("");
  const [busy, setBusy]         = useState(false);
  const [revealed, setRevealed] = useState(false);
  const [result, setResult]     = useState<{ score: number; words: number; iocsCited: number; iocsTotal: number; fabricatedCount: number; explanation: string } | null>(null);
  const [xpEarned, setXpEarned] = useState(0);
  const [passed, setPassed]     = useState(false);

  const wordCount = text.trim().split(/\s+/).filter(Boolean).length;

  async function submit() {
    setBusy(true);
    try {
      const res = await submitTask(roomId, task.id, { text });
      setResult({
        score: Number(res.reveal.score) || 0,
        words: Number(res.reveal.words) || 0,
        iocsCited: Number(res.reveal.iocsCited) || 0,
        iocsTotal: Number(res.reveal.iocsTotal) || 0,
        fabricatedCount: Number(res.reveal.fabricatedCount) || 0,
        explanation: typeof res.reveal.explanation === "string" ? res.reveal.explanation : "",
      });
      setXpEarned(res.xpEarned);
      setPassed(res.correct);
      setRevealed(true);
    } finally {
      setBusy(false);
    }
  }

  if (isCompleted) {
    return (
      <div className="space-y-4">
        <h2 className="text-xl font-bold text-white">{task.heading}</h2>
        <div className="inline-flex items-center gap-2 rounded border border-neon-green/40 bg-neon-green/10 px-3 py-1.5 text-sm text-neon-green">
          <CheckCircle2 className="h-4 w-4" />
          Already completed — +{task.xp} XP earned
        </div>
        <Button variant="primary" size="md" onClick={() => onComplete(0)}>
          Next Task <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <FileText className="h-5 w-5 text-cyber-300" />
        <h2 className="text-xl font-bold text-white">{task.heading}</h2>
      </div>
      <p className="text-sm text-slate-400 leading-relaxed">{task.context}</p>
      <p className="text-sm text-white font-medium">{task.prompt}</p>

      {!revealed && (
        <div className="rounded-lg border border-cyber-500/30 bg-cyber-500/5 p-3 space-y-1">
          <p className="text-xs font-semibold uppercase tracking-wider text-cyber-300">A strong answer will</p>
          <ul className="text-xs text-slate-300 space-y-0.5 list-disc list-inside">
            {task.rubricHints.map((hint, i) => <li key={i}>{hint}</li>)}
          </ul>
        </div>
      )}

      {!revealed && (
        <div className="space-y-2">
          <textarea
            value={text}
            onChange={e => setText(e.target.value)}
            disabled={busy}
            rows={10}
            placeholder="Write your report here…"
            className="w-full rounded-lg border border-border bg-[#080d14] p-4 font-mono text-sm leading-relaxed text-slate-200 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyber-500/30 resize-y"
          />
          <p className="text-xs text-slate-500">{wordCount} word{wordCount === 1 ? "" : "s"} (aim for {task.minWords}+)</p>
        </div>
      )}

      {!revealed && (
        <Button variant="primary" size="md" disabled={wordCount === 0 || busy} onClick={submit}>
          Submit Report
        </Button>
      )}

      {revealed && result && (
        <div className={cn("rounded-lg border p-4 text-sm space-y-2",
          passed ? "border-neon-green/40 bg-neon-green/10" : "border-neon-amber/40 bg-neon-amber/10",
        )}>
          <p className={cn("font-semibold", passed ? "text-neon-green" : "text-neon-amber")}>
            {passed ? `Passed — ${result.score}/100, +${xpEarned} XP` : `${result.score}/100 — below the pass bar`}
          </p>
          <p className="text-slate-300">
            {result.words} words · cited {result.iocsCited}/{result.iocsTotal} of the case's real indicators
            {result.fabricatedCount > 0 && <span className="text-severity-high"> · {result.fabricatedCount} cited indicator{result.fabricatedCount === 1 ? "" : "s"} not found anywhere in this case</span>}
          </p>
          <p className="text-slate-300">{result.explanation}</p>
        </div>
      )}

      {revealed && (
        <Button variant={passed ? "primary" : "secondary"} size="md" onClick={() => onComplete(xpEarned)}>
          Next <ChevronRight className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

// ─── Main TaskPlayer ────────────────────────────────────────────────────────────
export function TaskPlayer({ roomId, task, onComplete, isCompleted, prevLogEvent }: TaskPlayerProps) {
  // Behavioral telemetry (Phase 1 — see ANALYST_TELEMETRY_PLAN.md): timing is
  // captured here at the dispatcher, via event delegation, so none of the 7
  // sub-players below need to know telemetry exists. isCompleted tasks (the
  // student is just re-reading a finished task) never emit telemetry.
  const { recordInteraction, finalize } = useTaskTelemetry(task.id);

  const handleComplete = useCallback((xp: number) => {
    onComplete(xp, isCompleted ? undefined : finalize());
  }, [onComplete, finalize, isCompleted]);

  const player = (() => {
    switch (task.type) {
      case "reading":         return <ReadingPlayer      roomId={roomId} task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "question":        return <QuestionPlayer     roomId={roomId} task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "log_analysis":    return <LogAnalysisPlayer  roomId={roomId} task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "flag":            return <FlagPlayer         roomId={roomId} task={task} onComplete={handleComplete} isCompleted={isCompleted} prevLogEvent={prevLogEvent} />;
      case "analyst_choice":  return <AnalystChoicePlayer roomId={roomId} task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "matching":        return <MatchingPlayer     roomId={roomId} task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "ordering":        return <OrderingPlayer     roomId={roomId} task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "query_fill":      return <QueryFillPlayer    roomId={roomId} task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "written_report":  return <WrittenReportPlayer roomId={roomId} task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      default:                return null;
    }
  })();

  return (
    <div onClickCapture={recordInteraction} onChangeCapture={recordInteraction}>
      {player}
    </div>
  );
}
