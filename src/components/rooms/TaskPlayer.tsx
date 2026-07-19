"use client";
import React, { useState, useRef, useEffect, useCallback } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { ChevronRight, CheckCircle2, ChevronDown, Flag, Lightbulb, Tag, X, BookOpen, Shield } from "lucide-react";
import type { RoomTask, ReadingTask, QuestionTask, LogAnalysisTask, FlagTask, AnalystChoiceTask, MatchingTask, OrderingTask, QueryFillTask } from "@/data/rooms";
import type { TelemetryEvent } from "@/lib/sim/types";
import { useTaskTelemetry, type TaskTelemetryEntry } from "@/lib/useTaskTelemetry";
import { MermaidDiagram } from "./MermaidDiagram";

interface TaskPlayerProps {
  task: RoomTask;
  onComplete: (xpEarned: number, telemetry?: TaskTelemetryEntry) => void;
  isCompleted: boolean;
  prevLogEvent?: TelemetryEvent;
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
      <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-2 px-0.5">Tag as IOC type</p>
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
        <BookOpen className="h-5 w-5 text-slate-600 mx-auto mb-2" />
        <p className="text-xs text-slate-500">Click any field value in the log to tag it as an IOC indicator.</p>
      </div>
    );
  }
  return (
    <div className="rounded-lg border border-cyber-500/20 bg-[#080d14] overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-cyber-500/20 bg-cyber-500/5">
        <Shield className="h-3.5 w-3.5 text-cyber-400" />
        <span className="text-[11px] font-bold uppercase tracking-wider text-cyber-400">IOC Notebook</span>
        <span className="ml-auto text-[10px] font-mono text-slate-500">{iocs.length} indicator{iocs.length !== 1 ? "s" : ""}</span>
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
                <p className="text-[10px] text-slate-500 truncate">{ioc.field}</p>
                <p className="text-xs font-mono text-white break-all leading-relaxed">{ioc.value}</p>
              </div>
              <button
                onClick={() => onRemove(i)}
                className="opacity-0 group-hover:opacity-100 transition-opacity mt-0.5 text-slate-600 hover:text-slate-300"
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
function InteractiveLogEventCard({
  event, iocs, onTag, onUntag,
}: { event: TelemetryEvent; iocs: IocEntry[]; onTag: (entry: IocEntry) => void; onUntag: (value: string) => void; }) {
  const [expanded, setExpanded] = useState(true);
  const [popover, setPopover] = useState<PopoverState | null>(null);
  const colors = SOURCE_COLORS[event.source] ?? SOURCE_COLORS.edr;

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
          <span className="ml-auto text-[10px] font-mono text-slate-500">{event.ts}</span>
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
            <span className="ml-auto text-[10px] text-slate-600">{Object.keys(event.raw).length} fields</span>
          </button>
          {expanded && (
            <div className="px-4 pb-4 pt-1 font-mono text-[11px] space-y-0.5 max-h-80 overflow-y-auto">
              {Object.entries(event.raw).map(([k, v]) => {
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
          : "border-border/40 bg-bg-elevated/30 text-slate-500"
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
function ReadingPlayer({ task, onComplete, isCompleted }: { task: ReadingTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  return (
    <div className="space-y-7">
      <h2 className="text-3xl font-bold text-white leading-tight">{task.heading}</h2>
      <RichContent content={task.content} />
      {task.diagram && <MermaidDiagram chart={task.diagram} caption={task.diagramCaption} />}
      {task.codeExample && (
        <div className="rounded-lg border border-border bg-[#080d14] overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-bg-elevated/40">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Example</span>
          </div>
          <pre className="px-4 py-4 font-mono text-sm text-cyber-300 overflow-x-auto leading-relaxed whitespace-pre-wrap">
            {task.codeExample}
          </pre>
        </div>
      )}
      {!isCompleted && (
        <Button onClick={() => onComplete(0)} variant="primary" size="md">
          <CheckCircle2 className="h-4 w-4" />
          Mark as Read
        </Button>
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
function QuestionPlayer({ task, onComplete, isCompleted }: { task: QuestionTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [selected, setSelected]   = useState<number | null>(null);
  const [revealed, setReveal]     = useState(isCompleted);
  const [confirmed, setConfirmed] = useState(isCompleted);
  // One forgiving second chance: a wrong first answer does NOT reveal the correct
  // option — the student gets a nudge and one more try for half credit. Two tries
  // only (options are few, so unlimited retries would be brute-forceable).
  const [wrongOnce, setWrongOnce] = useState(false);

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

  const correct = selected === task.answer;
  const awardedXp = wrongOnce ? Math.ceil(task.xp / 2) : task.xp;

  function handleConfirm() {
    if (selected === task.answer) {
      setReveal(true); setConfirmed(true);          // correct → award (full or half)
    } else if (!wrongOnce) {
      setWrongOnce(true); setSelected(null);        // first miss → nudge + one more try, no reveal
    } else {
      setReveal(true); setConfirmed(true);          // second miss → reveal + 0 XP
    }
  }

  return (
    <div className="space-y-5">
      <p className="text-slate-200 leading-relaxed text-base">{task.question}</p>
      <div className="space-y-2">
        {task.options.map((opt, idx) => (
          <OptionButton
            key={idx} label={opt} index={idx}
            selected={selected === idx} revealed={revealed} correctIndex={task.answer}
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
        <Button variant="primary" size="md" disabled={selected === null} onClick={handleConfirm}>
          {wrongOnce ? "Try Again" : "Confirm Answer"}
        </Button>
      )}
      {revealed && (
        <div className={cn("rounded-lg border p-4 text-sm",
          correct ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-severity-high/40 bg-severity-high/10 text-severity-high",
        )}>
          <p className="font-semibold mb-1">{correct ? `Correct! +${awardedXp} XP` : "Incorrect"}</p>
          <p className="text-slate-300">{task.explanation}</p>
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
function LogAnalysisPlayer({ task, onComplete, isCompleted }: { task: LogAnalysisTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [iocs, setIocs]           = useState<IocEntry[]>([]);
  const [answers, setAnswers]     = useState<(number | null)[]>(Array(task.questions.length).fill(null));
  const [revealed, setRevealed]   = useState<boolean[]>(Array(task.questions.length).fill(false));
  const [confirmed, setConfirmed] = useState<boolean[]>(Array(task.questions.length).fill(false));
  const [totalXp, setTotalXp]     = useState(0);

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

  function confirmAnswer(i: number) {
    const isCorrect = answers[i] === task.questions[i].answer;
    const xpGained  = isCorrect ? task.questions[i].xp : 0;
    setRevealed(prev  => prev.map((v, idx) => idx === i ? true : v));
    setConfirmed(prev => prev.map((v, idx) => idx === i ? true : v));
    setTotalXp(prev => prev + xpGained);
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
          const isCorrect = answers[i] === q.answer;
          return (
            <div key={i} className="space-y-3">
              <p className="text-sm font-semibold text-white">
                <span className="text-slate-500 mr-2">Q{i + 1}.</span>
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
                    <span className="text-[10px] text-slate-500 self-center">+{iocs.length - 4} more in notebook</span>
                  )}
                </div>
              )}

              <div className="space-y-2">
                {q.options.map((opt, idx) => (
                  <OptionButton
                    key={idx} label={opt} index={idx}
                    selected={answers[i] === idx} revealed={revealed[i]} correctIndex={q.answer}
                    onSelect={() => !revealed[i] && setAnswers(prev => prev.map((v, j) => j === i ? idx : v))}
                  />
                ))}
              </div>
              {!confirmed[i] && (
                <Button variant="secondary" size="sm" disabled={answers[i] === null}
                  onClick={() => confirmAnswer(i)}>
                  Confirm
                </Button>
              )}
              {revealed[i] && (
                <div className={cn("rounded-lg border p-3 text-sm",
                  isCorrect ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-severity-high/40 bg-severity-high/10 text-severity-high",
                )}>
                  <p className="font-semibold mb-1">{isCorrect ? `Correct! +${q.xp} XP` : "Incorrect"}</p>
                  <p className="text-slate-300">{q.explanation}</p>
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
function FlagPlayer({ task, onComplete, isCompleted, prevLogEvent }: { task: FlagTask; onComplete: (xp: number) => void; isCompleted: boolean; prevLogEvent?: TelemetryEvent }) {
  const [input, setInput]       = useState("");
  const [status, setStatus]     = useState<"idle" | "correct" | "wrong">("idle");
  const [showHint, setShowHint] = useState(false);

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

  function submit() {
    if (input.trim().toLowerCase() === task.answer.trim().toLowerCase()) {
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
              "h-10 flex-1 rounded-md border bg-[#080d14] px-3 font-mono text-sm text-white placeholder-slate-600",
              "focus:outline-none focus:ring-2",
              status === "wrong"
                ? "border-severity-high/50 focus:ring-severity-high/30"
                : "border-cyber-500/40 focus:ring-cyber-500/30 focus:border-cyber-500/60",
            )}
          />
          <Button variant="primary" size="md" onClick={submit} disabled={!input.trim()}>Submit</Button>
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
            Correct! +{task.xp} XP
          </div>
          <Button variant="primary" size="md" onClick={() => onComplete(task.xp)}>
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
        <span className="ml-auto text-[10px] font-mono text-slate-500">{event.ts}</span>
      </div>
      <div>
        <button
          onClick={() => setExpanded(v => !v)}
          className="flex w-full items-center gap-2 px-4 py-2 text-[11px] text-slate-400 hover:text-slate-200 hover:bg-bg-elevated/40 transition-colors"
        >
          <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", expanded && "rotate-180")} />
          Raw Fields
          <span className="ml-auto text-[10px] text-slate-600">{Object.keys(event.raw).length} fields</span>
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
function AnalystChoicePlayer({ task, onComplete, isCompleted }: { task: AnalystChoiceTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);
  // One forgiving second chance at half credit; a wrong first verdict does not
  // reveal the correct one (only 4 verdicts, so unlimited retries would be trivial).
  const [wrongOnce, setWrongOnce] = useState(false);
  const awardedXp = wrongOnce ? Math.ceil(task.xp / 2) : task.xp;

  function handleSubmit() {
    if (selected === task.correct_verdict) setRevealed(true);
    else if (!wrongOnce) { setWrongOnce(true); setSelected(null); }
    else setRevealed(true);
  }

  const VERDICTS = [
    { key: "true_positive",  label: "True Positive",   desc: "Real threat — take action now",   activeClass: "border-red-500/70 bg-red-500/15 text-red-300"          },
    { key: "false_positive", label: "False Positive",  desc: "Benign — close this alert",       activeClass: "border-neon-green/70 bg-neon-green/15 text-neon-green"  },
    { key: "escalate",       label: "Escalate to T2",  desc: "Needs senior analyst review",     activeClass: "border-neon-amber/70 bg-neon-amber/15 text-neon-amber"  },
    { key: "informational",  label: "Informational",   desc: "Log and monitor — no action",     activeClass: "border-slate-500/70 bg-slate-500/15 text-slate-300"     },
  ] as const;

  const isCorrect = selected === task.correct_verdict;

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
                  ? v.key === task.correct_verdict
                    ? "border-neon-green/60 bg-neon-green/10 text-neon-green cursor-default"
                    : selected === v.key && !isCorrect
                      ? "border-severity-high/50 bg-severity-high/10 text-severity-high cursor-default"
                      : "border-border/30 bg-bg-elevated/20 text-slate-600 cursor-default"
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
        <Button variant="primary" size="md" disabled={!selected} onClick={handleSubmit}>
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
          <p className="text-slate-300">{task.explanation}</p>
          {task.fp_trap && !isCorrect && (
            <div className="mt-2 border-l-2 border-neon-amber/40 pl-3">
              <p className="text-[11px] uppercase tracking-wider text-neon-amber font-semibold mb-0.5">Common trap</p>
              <p className="text-xs text-neon-amber/80">{task.fp_trap}</p>
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
function MatchingPlayer({ task, onComplete, isCompleted }: { task: MatchingTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [selectedLeft, setSelectedLeft] = useState<string | null>(null);
  const [connections, setConnections] = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState(false);

  const shuffledRight = React.useMemo(() => {
    const n = task.pairs.length;
    return task.pairs.map((_, i) => task.pairs[(i + Math.ceil(n / 2)) % n]);
  }, [task.pairs]);

  const allConnected = Object.keys(connections).length === task.pairs.length;
  const correctCount = task.pairs.filter(p => connections[p.id] === p.id).length;
  const allCorrect = correctCount === task.pairs.length;

  function handleLeftClick(pairId: string) {
    if (revealed) return;
    setSelectedLeft(prev => prev === pairId ? null : pairId);
  }

  function handleRightClick(rightPairId: string) {
    if (revealed || !selectedLeft) return;
    setConnections(prev => ({ ...prev, [selectedLeft]: rightPairId }));
    setSelectedLeft(null);
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
          <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">Match from</p>
          {task.pairs.map(pair => {
            const connectedRightId = connections[pair.id];
            const isSelected = selectedLeft === pair.id;
            const isCorrect = revealed && connectedRightId === pair.id;
            const isWrong  = revealed && connectedRightId !== undefined && connectedRightId !== pair.id;
            return (
              <button
                key={pair.id}
                onClick={() => handleLeftClick(pair.id)}
                disabled={revealed}
                className={cn(
                  "w-full rounded-lg border px-3 py-2.5 text-left text-sm transition-all",
                  revealed
                    ? isCorrect ? "border-neon-green/60 bg-neon-green/10 text-neon-green"
                      : isWrong ? "border-severity-high/50 bg-severity-high/10 text-severity-high"
                      : "border-border/40 bg-bg-elevated/30 text-slate-500"
                    : isSelected ? "border-cyber-500/70 bg-cyber-500/15 text-white"
                    : connectedRightId ? "border-cyber-500/30 bg-cyber-500/5 text-white"
                    : "border-border/50 bg-bg-elevated/40 text-slate-300 hover:border-cyber-500/40 hover:text-white",
                )}
              >
                <span className="font-medium">{pair.left}</span>
                {connectedRightId && !revealed && (
                  <span className="mt-0.5 block text-[10px] text-cyber-400">connected</span>
                )}
              </button>
            );
          })}
        </div>

        {/* Right column */}
        <div className="space-y-2">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">
            {selectedLeft ? "Click to connect" : "Select left first"}
          </p>
          {shuffledRight.map(pair => {
            const connectedLeftId = Object.entries(connections).find(([, rId]) => rId === pair.id)?.[0];
            const isConnected = !!connectedLeftId;
            const isCorrect = revealed && connectedLeftId === pair.id;
            const isWrong  = revealed && connectedLeftId !== undefined && connectedLeftId !== pair.id;
            return (
              <button
                key={pair.id}
                onClick={() => handleRightClick(pair.id)}
                disabled={revealed || !selectedLeft}
                className={cn(
                  "w-full rounded-lg border px-3 py-2.5 text-left text-sm transition-all",
                  revealed
                    ? isCorrect ? "border-neon-green/60 bg-neon-green/10 text-neon-green"
                      : isWrong ? "border-severity-high/50 bg-severity-high/10 text-severity-high"
                      : "border-border/40 bg-bg-elevated/30 text-slate-500"
                    : selectedLeft && !isConnected ? "border-cyber-500/40 bg-cyber-500/5 text-slate-200 hover:border-cyber-500/70 hover:text-white cursor-pointer"
                    : isConnected ? "border-cyber-500/30 bg-cyber-500/5 text-white"
                    : "border-border/50 bg-bg-elevated/40 text-slate-300 cursor-default",
                )}
              >
                {pair.right}
              </button>
            );
          })}
        </div>
      </div>

      {!revealed && (
        <p className="text-xs text-slate-500">
          {Object.keys(connections).length}/{task.pairs.length} pairs connected
          {selectedLeft ? " — now click an item on the right" : " — select an item on the left to begin"}
        </p>
      )}

      {!revealed && allConnected && (
        <Button variant="primary" size="md" onClick={() => setRevealed(true)}>
          Check Matches
        </Button>
      )}

      {revealed && (
        <div className={cn("rounded-lg border p-4 text-sm space-y-2",
          allCorrect ? "border-neon-green/40 bg-neon-green/10" : "border-neon-amber/40 bg-neon-amber/10",
        )}>
          <p className={cn("font-semibold", allCorrect ? "text-neon-green" : "text-neon-amber")}>
            {allCorrect ? `Perfect! +${task.xp} XP` : `${correctCount}/${task.pairs.length} correct`}
          </p>
          <p className="text-slate-300">{task.explanation}</p>
        </div>
      )}

      {revealed && (
        <Button variant={allCorrect ? "primary" : "secondary"} size="md"
          onClick={() => onComplete(allCorrect ? task.xp : Math.floor(task.xp * correctCount / task.pairs.length))}>
          Next <ChevronRight className="h-4 w-4" />
        </Button>
      )}
    </div>
  );
}

// ─── Ordering Task ────────────────────────────────────────────────────────────────
function OrderingPlayer({ task, onComplete, isCompleted }: { task: OrderingTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [placed, setPlaced] = useState<(string | null)[]>(Array(task.items.length).fill(null));
  const [selectedItem, setSelectedItem] = useState<string | null>(null);
  const [revealed, setRevealed] = useState(false);

  const shuffledItems = React.useMemo(() => {
    const n = task.items.length;
    return task.items.map((_, i) => task.items[(i + Math.ceil(n / 2)) % n]);
  }, [task.items]);

  const allPlaced = placed.every(Boolean);
  const placedSet = new Set(placed.filter(Boolean) as string[]);
  const correctCount = placed.filter((id, i) => id === task.correct_order[i]).length;
  const allCorrect = correctCount === task.items.length;
  const xpEarned = allCorrect ? task.xp : Math.floor(task.xp * correctCount / task.items.length);

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
          <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">Correct Order</p>
          {task.items.map((_, slotIdx) => {
            const placedId = placed[slotIdx];
            const placedItem = placedId ? task.items.find(i => i.id === placedId) : null;
            const isCorrect = revealed && placedId === task.correct_order[slotIdx];
            const isWrong  = revealed && placedId && placedId !== task.correct_order[slotIdx];
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
                    : "text-slate-600 italic",
                )}>
                  {placedItem ? placedItem.text : "— empty —"}
                </span>
              </button>
            );
          })}
        </div>

        {/* Items pool */}
        <div className="space-y-2">
          <p className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold">
            {selectedItem ? "Now click a numbered slot" : "Select an item to place"}
          </p>
          {shuffledItems.map(item => {
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
                      ? "border-border/20 bg-bg-elevated/20 text-slate-600 cursor-pointer"
                      : "border-border/50 bg-bg-elevated/40 text-slate-300 hover:border-cyber-500/40 hover:text-white cursor-pointer",
                )}
              >
                {item.text}
                {isPlaced && <span className="ml-2 text-[10px] text-slate-600">(placed — click to move)</span>}
              </button>
            );
          })}
        </div>
      </div>

      {!revealed && (
        <p className="text-xs text-slate-500">
          {placed.filter(Boolean).length}/{task.items.length} items placed
          {selectedItem ? " — click a numbered slot on the left" : ""}
        </p>
      )}

      {!revealed && allPlaced && (
        <Button variant="primary" size="md" onClick={() => setRevealed(true)}>
          Submit Order
        </Button>
      )}

      {revealed && (
        <div className={cn("rounded-lg border p-4 text-sm space-y-2",
          allCorrect ? "border-neon-green/40 bg-neon-green/10" : "border-neon-amber/40 bg-neon-amber/10",
        )}>
          <p className={cn("font-semibold", allCorrect ? "text-neon-green" : "text-neon-amber")}>
            {allCorrect ? `Perfect order! +${task.xp} XP` : `${correctCount}/${task.items.length} in the correct position`}
          </p>
          <p className="text-slate-300">{task.explanation}</p>
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

function normalizeAnswer(s: string): string {
  return s.trim().toLowerCase().replace(/\s+/g, " ").replace(/^["']|["']$/g, "");
}

function QueryFillPlayer({ task, onComplete, isCompleted }: { task: QueryFillTask; onComplete: (xp: number) => void; isCompleted: boolean }) {
  const [values, setValues]     = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState(false);

  // Split the template into alternating text / {{blankId}} segments, keeping
  // the delimiters so we know exactly where each input goes.
  const segments = React.useMemo(() => task.template.split(BLANK_TOKEN), [task.template]);

  const blankIds = task.blanks.map(b => b.id);
  const allFilled = blankIds.every(id => (values[id] ?? "").trim().length > 0);
  const isBlankCorrect = (id: string) => {
    const blank = task.blanks.find(b => b.id === id);
    if (!blank) return false;
    const given = normalizeAnswer(values[id] ?? "");
    return blank.answers.some(a => normalizeAnswer(a) === given);
  };
  const correctCount = blankIds.filter(isBlankCorrect).length;
  const allCorrect   = correctCount === blankIds.length;
  const xpEarned      = allCorrect ? task.xp : Math.floor(task.xp * correctCount / Math.max(1, blankIds.length));

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
              <span className="font-mono">{b.placeholder ?? b.id}</span>: expected <span className="font-mono text-slate-300">{b.answers[0]}</span>
            </p>
          ))}
        </div>
      )}

      {!revealed && (
        <Button variant="primary" size="md" disabled={!allFilled} onClick={() => setRevealed(true)}>
          Run Query
        </Button>
      )}

      {revealed && (
        <div className={cn("rounded-lg border p-4 text-sm space-y-2",
          allCorrect ? "border-neon-green/40 bg-neon-green/10" : "border-neon-amber/40 bg-neon-amber/10",
        )}>
          <p className={cn("font-semibold", allCorrect ? "text-neon-green" : "text-neon-amber")}>
            {allCorrect ? `Correct! +${task.xp} XP` : `${correctCount}/${blankIds.length} blanks correct`}
          </p>
          <p className="text-slate-300">{task.explanation}</p>
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

// ─── Main TaskPlayer ────────────────────────────────────────────────────────────
export function TaskPlayer({ task, onComplete, isCompleted, prevLogEvent }: TaskPlayerProps) {
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
      case "reading":         return <ReadingPlayer      task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "question":        return <QuestionPlayer     task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "log_analysis":    return <LogAnalysisPlayer  task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "flag":            return <FlagPlayer         task={task} onComplete={handleComplete} isCompleted={isCompleted} prevLogEvent={prevLogEvent} />;
      case "analyst_choice":  return <AnalystChoicePlayer task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "matching":        return <MatchingPlayer     task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "ordering":        return <OrderingPlayer     task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      case "query_fill":      return <QueryFillPlayer    task={task} onComplete={handleComplete} isCompleted={isCompleted} />;
      default:                return null;
    }
  })();

  return (
    <div onClickCapture={recordInteraction} onChangeCapture={recordInteraction}>
      {player}
    </div>
  );
}
