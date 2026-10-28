"use client";
import { ApiError, messageFromResponse, userMessageFor } from "@/lib/http/apiError";
import { useState, useEffect, useRef } from "react";
import { X, FileText, Shield, AlertTriangle, CheckCircle2, Loader2, ChevronUp, ChevronDown, Trash2, Plus, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import { Term } from "@/components/ui/Term";
import type { IncidentReportResponse } from "@/app/api/dashboard/incident-report/route";
import { IOC_ROLES, PASS_RULES, type Difficulty, type IocRow, type TimelineReport, type TimelineRow, type TruthEvent } from "@/lib/dashboard/timelineReport";

type Phase = "form" | "grading" | "result";

/** Format a millisecond duration as "Xm Ys" for the response-time coaching line. */
function fmtDuration(ms: number): string {
  const total = Math.max(0, Math.round(ms / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${m}m ${s}s`;
}

function ScoreRing({ score }: { score: number }) {
  const radius = 36;
  const circ   = 2 * Math.PI * radius;
  const offset = circ - (score / 100) * circ;
  const color  = score >= 80 ? "#22c55e" : score >= 60 ? "#3b82f6" : score >= 40 ? "#f59e0b" : "#ef4444";

  return (
    <svg width="96" height="96" viewBox="0 0 96 96" role="img" aria-label={`Score ${score} out of 100`}>
      <circle cx="48" cy="48" r={radius} fill="none" stroke="#1e293b" strokeWidth="8" />
      <circle
        cx="48" cy="48" r={radius}
        fill="none"
        stroke={color}
        strokeWidth="8"
        strokeDasharray={`${circ} ${circ}`}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform="rotate(-90 48 48)"
        style={{ transition: "stroke-dashoffset 0.8s ease" }}
      />
      <text x="48" y="44" textAnchor="middle" fill={color} fontSize="20" fontWeight="bold" fontFamily="monospace">
        {score}
      </text>
      <text x="48" y="60" textAnchor="middle" fill="#8190a5" fontSize="10" fontFamily="sans-serif">
        / 100
      </text>
    </svg>
  );
}

interface Props {
  companyName: string;
  /** Real indicator values from the actual attack — grader ground truth */
  realIndicators: string[];
  /**
   * Serialized feed (raw included). The grader treats any value the student lists that
   * appears in this text as REAL — so a value visible in a log's raw block is never
   * mis-flagged as "fabricated" just because it wasn't in the discrete list.
   */
  evidenceText?: string;
  attackTitle: string | null;
  /** MITRE technique IDs the real attack used — sent to grader as ground truth */
  attackMitreTechniques?: string[];
  /** The attack's logs as shown in the feed: each timeline row is matched against them. */
  truthEvents: TruthEvent[];
  /** The session's difficulty: sets what the report needs to pass. */
  difficulty: Difficulty;
  /** The report itself. It lives in the page, so "Add to timeline" on an open log
   *  reaches it while the drawer is open, and closing the drawer never loses it. */
  report: TimelineReport;
  onReportChange: (next: TimelineReport) => void;
  /** Indicator values on the given feed logs (the student's own timeline rows). */
  indicatorsOf: (eventIds: string[]) => string[];
  /**
   * Benign "decoy" events the student saw this session, each with the written
   * explanation of why it is a false positive. Revealed only in the passed
   * state as a teaching debrief (never before/on failure — see render).
   */
  decoys?: { label: string; source: string; fp_explanation: string }[];
  /** Response time (ms) for this incident — from the attack's first phase to the
   *  catch / this report. Surfaced as a coaching point below; it NEVER affects
   *  pass/fail or the score. null when unmeasured. */
  responseMs?: number | null;
  /** Response-time target in seconds — the coaching benchmark (default 15 min). */
  responseTargetSeconds?: number;
  /** True when a passing report would close and credit an open incident. False
   *  when no incident is open (the attack has not started) or it was already
   *  credited: the result then says so instead of "objective unlocked". */
  creditsIncident?: boolean;
  onClose: () => void;
  onPassed: (score: number) => void;
}

const field = "w-full rounded border border-border/60 bg-bg px-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:border-cyber-500/40 focus:outline-none";
const label = "text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-400";
const newId = () => Math.random().toString(36).slice(2, 10);

export function IncidentReportModal({
  companyName,
  realIndicators,
  evidenceText,
  attackTitle,
  attackMitreTechniques,
  truthEvents,
  difficulty,
  report,
  onReportChange,
  indicatorsOf,
  decoys = [],
  responseMs = null,
  responseTargetSeconds = 900,
  creditsIncident = true,
  onClose,
  onPassed,
}: Props) {
  const [phase,   setPhase]   = useState<Phase>("form");
  const [error,   setError]   = useState<string | null>(null);
  const [result,  setResult]  = useState<IncidentReportResponse | null>(null);
  const [passed,  setPassed]  = useState(false);
  // Whether THIS submission credited an incident: captured at submit time, since
  // the parent's prop flips to false the moment the pass is counted.
  const [credited, setCredited] = useState(false);

  const set = (patch: Partial<TimelineReport>) => onReportChange({ ...report, ...patch });
  const setRow = (id: string, patch: Partial<TimelineRow>) => set({ rows: report.rows.map(r => (r.id === id ? { ...r, ...patch } : r)) });
  const moveRow = (i: number, d: -1 | 1) => {
    const j = i + d;
    if (j < 0 || j >= report.rows.length) return;
    const rows = [...report.rows];
    [rows[i], rows[j]] = [rows[j], rows[i]];
    set({ rows });
  };
  const setIoc = (id: string, patch: Partial<IocRow>) => set({ iocs: report.iocs.map(r => (r.id === id ? { ...r, ...patch } : r)) });
  const collectIocs = () => {
    const have = new Set(report.iocs.map(i => i.value.trim().toLowerCase()));
    const found = indicatorsOf(report.rows.map(r => r.eventId).filter((x): x is string => !!x))
      .filter(v => !have.has(v.toLowerCase()));
    if (found.length) set({ iocs: [...report.iocs, ...found.map(v => ({ id: newId(), value: v, role: "" as const }))] });
  };

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  // a11y: this is a deliberately NON-modal drawer (the feed beside it must stay
  // clickable while the analyst writes), so focus is not trapped — but focus
  // moves into it on open and returns to whatever opened it when it closes.
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    return () => { if (previous && document.contains(previous)) previous.focus(); };
  }, []);

  // Move focus to the verdict when grading finishes so it is announced.
  const resultRef = useRef<HTMLDivElement>(null);
  useEffect(() => { if (phase === "result") resultRef.current?.focus(); }, [phase]);

  const canSubmit = report.rows.length > 0 && report.summary.trim().length >= 20;
  const rule = PASS_RULES[difficulty];
  const diffLabel = difficulty[0].toUpperCase() + difficulty.slice(1);

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setError(null);
    setPhase("grading");
    const willCredit = creditsIncident;

    try {
      const res = await fetch("/api/dashboard/incident-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          company: companyName,
          attackTitle: attackTitle ?? undefined,
          attackMitreTechniques: attackMitreTechniques ?? [],
          realIndicators,
          evidenceText,
          timelineReport: report,
          truthEvents,
          difficulty,
        }),
      });

      if (!res.ok) throw new ApiError(await messageFromResponse(res), res.status);
      const data: IncidentReportResponse = await res.json();
      setResult(data);
      setPassed(data.passed);
      setCredited(data.passed && willCredit);
      if (data.passed) onPassed(data.score);
      setPhase("result");
    } catch (e) {
      // NEVER fail-open. A network/grader failure must not award a pass. Send the
      // analyst back to the form with a retry prompt; the report is kept.
      setError(`Couldn't grade the report: ${userMessageFor(e)} Your report is saved below.`);   // E-09
      setPhase("form");
    }
  };

  return (
    /* Docked as a side drawer, NOT a centered modal with a blocking backdrop.
       The report explicitly asks the analyst to quote IOCs from the logs
       "exactly" — so covering the event feed while they write made the task
       self-defeating. With no full-screen overlay the feed stays visible AND
       clickable: rows can still be expanded to re-read raw fields mid-write,
       which is how a real analyst works (SIEM on one side, case ticket on the
       other). Full width on narrow screens where side-by-side isn't possible. */
    <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-full lg:w-[480px]"
      role="dialog" aria-modal="false" aria-labelledby="incident-report-title">
      <div className="relative flex h-full w-full flex-col border-l border-border bg-bg-elevated shadow-2xl shadow-black/60">
        <div className="h-1 w-full shrink-0 bg-gradient-to-r from-cyber-500 via-neon-purple to-neon-green" />

        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-4">

          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <FileText className="h-5 w-5 text-cyber-300 shrink-0" />
              <div>
                <p className="text-[9px] font-bold uppercase tracking-[0.2em] text-slate-400">Tier-1 incident report</p>
                <h2 id="incident-report-title" className="text-sm font-bold text-white">Incident report: {companyName}</h2>
              </div>
            </div>
            <button type="button" onClick={onClose} aria-label="Close incident report" className="rounded p-1 text-slate-400 hover:text-white transition">
              <X aria-hidden="true" className="h-4 w-4" />
            </button>
          </div>

          {/* ── FORM phase ── */}
          {phase === "form" && (
            <>
              {error && (
                <div className="rounded border border-severity-high/40 bg-severity-high/10 px-3 py-2.5 text-sm text-severity-high" role="alert">
                  {error}
                </div>
              )}
              <div className="rounded border border-neon-amber/20 bg-neon-amber/5 px-3 py-2.5">
                <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-neon-amber">Escalation to Tier-2 · {diffLabel}</p>
                <p className="text-[11px] leading-relaxed text-slate-300">
                  Rebuild the attack end to end: what ran, who ran it, where, and the log that proves each step. Then list the <Term k="ioc">IOCs</Term>, sum up the impact and hand the case over.
                </p>
                <p className="mt-1.5 text-[10px] text-slate-400">
                  To pass at {diffLabel}: {rule.score}/100, at least {Math.round(rule.coverage * 100)}% of the attack stages in your timeline, {rule.iocs} real indicator{rule.iocs > 1 ? "s" : ""}
                  {rule.handoff === "filled" ? ", a full handoff" : rule.handoff === "fit" ? ", a full handoff with a next step that stops the attack" : ""}
                  {rule.order > 0 ? ", steps in the right order" : ""}.
                </p>
              </div>

              {/* 1. Timeline */}
              <section aria-labelledby="ir-tl-label" className="space-y-2">
                <div className="flex items-center justify-between">
                  <p id="ir-tl-label" className={label}>1 · Attack timeline</p>
                  <span className="text-[10px] text-slate-500">{report.rows.length} step{report.rows.length === 1 ? "" : "s"}</span>
                </div>
                {report.rows.length === 0 && (
                  <p className="rounded border border-dashed border-border/60 px-3 py-3 text-[11px] leading-relaxed text-slate-400">
                    Open a log in the feed and press <span className="font-semibold text-cyber-200">Add to timeline</span>. Time, host and who ran it fill in from the log; you say what happened.
                  </p>
                )}
                <ol className="space-y-2">
                  {report.rows.map((r, i) => (
                    <li key={r.id} className="rounded border border-border/60 bg-bg/60 p-2">
                      <div className="mb-1.5 flex items-center gap-2">
                        <span className="font-mono text-[10px] font-bold text-cyber-300">#{i + 1}</span>
                        <input aria-label={`Step ${i + 1} time`} value={r.time} onChange={e => setRow(r.id, { time: e.target.value })} placeholder="09:16:02" className={cn(field, "w-24 py-1 font-mono")} />
                        {r.eventId
                          ? <span className="rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 text-[9px] font-semibold text-cyber-200">from a log</span>
                          : <span className="rounded border border-border px-1.5 py-0.5 text-[9px] text-slate-400">typed</span>}
                        <span className="ml-auto flex items-center gap-0.5">
                          <button type="button" aria-label={`Move step ${i + 1} up`} disabled={i === 0} onClick={() => moveRow(i, -1)} className="rounded p-0.5 text-slate-400 hover:text-white disabled:opacity-30"><ChevronUp className="h-3.5 w-3.5" aria-hidden /></button>
                          <button type="button" aria-label={`Move step ${i + 1} down`} disabled={i === report.rows.length - 1} onClick={() => moveRow(i, 1)} className="rounded p-0.5 text-slate-400 hover:text-white disabled:opacity-30"><ChevronDown className="h-3.5 w-3.5" aria-hidden /></button>
                          <button type="button" aria-label={`Remove step ${i + 1}`} onClick={() => set({ rows: report.rows.filter(x => x.id !== r.id) })} className="rounded p-0.5 text-slate-400 hover:text-severity-high"><Trash2 className="h-3.5 w-3.5" aria-hidden /></button>
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-1.5">
                        <input aria-label={`Step ${i + 1} host`} value={r.host} onChange={e => setRow(r.id, { host: e.target.value })} placeholder="Host" className={cn(field, "font-mono")} />
                        <input aria-label={`Step ${i + 1} who ran it`} value={r.actor} onChange={e => setRow(r.id, { actor: e.target.value })} placeholder="Who ran it (account / process)" className={cn(field, "font-mono")} />
                      </div>
                      <textarea aria-label={`Step ${i + 1} what ran or happened`} rows={2} value={r.action} onChange={e => setRow(r.id, { action: e.target.value })}
                        placeholder="What ran / what happened, in your words" className={cn(field, "mt-1.5 resize-none leading-relaxed")} />
                    </li>
                  ))}
                </ol>
                <button type="button" onClick={() => set({ rows: [...report.rows, { id: newId(), time: "", host: "", actor: "", action: "" }] })}
                  className="flex items-center gap-1 text-[11px] text-slate-400 transition hover:text-cyber-200">
                  <Plus className="h-3.5 w-3.5" aria-hidden /> Add a step by hand
                </button>
              </section>

              {/* 2. Indicators */}
              <section aria-labelledby="ir-ioc-label" className="space-y-2">
                <div className="flex items-center justify-between">
                  <p id="ir-ioc-label" className={label}>2 · Indicators</p>
                  {report.rows.some(r => r.eventId) && (
                    <button type="button" onClick={collectIocs} className="text-[10px] font-semibold text-cyber-300 hover:text-cyber-100">Collect from my timeline</button>
                  )}
                </div>
                {report.iocs.map((x, i) => (
                  <div key={x.id} className="flex items-center gap-1.5">
                    <input aria-label={`Indicator ${i + 1} value`} value={x.value} onChange={e => setIoc(x.id, { value: e.target.value })} placeholder="IP, domain, hash, account, host" className={cn(field, "min-w-0 flex-1 font-mono")} />
                    <select aria-label={`Indicator ${i + 1} role`} value={x.role} onChange={e => setIoc(x.id, { role: e.target.value as IocRow["role"] })} className={cn(field, "w-44 shrink-0", !x.role && "text-slate-500")}>
                      <option value="">Choose role</option>
                      {IOC_ROLES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
                    </select>
                    <button type="button" aria-label={`Remove indicator ${i + 1}`} onClick={() => set({ iocs: report.iocs.filter(y => y.id !== x.id) })} className="shrink-0 rounded p-0.5 text-slate-400 hover:text-severity-high"><Trash2 className="h-3.5 w-3.5" aria-hidden /></button>
                  </div>
                ))}
                <button type="button" onClick={() => set({ iocs: [...report.iocs, { id: newId(), value: "", role: "" }] })}
                  className="flex items-center gap-1 text-[11px] text-slate-400 transition hover:text-cyber-200">
                  <Plus className="h-3.5 w-3.5" aria-hidden /> Add an indicator
                </button>
              </section>

              {/* 3. Summary */}
              <section className="space-y-1.5">
                <p id="ir-sum-label" className={label}>3 · Summary and impact</p>
                <textarea aria-labelledby="ir-sum-label" aria-required rows={3} value={report.summary} onChange={e => set({ summary: e.target.value })}
                  placeholder="What the attack is (name the technique), how far it got, and what it puts at risk."
                  className={cn(field, "resize-none leading-relaxed")} />
              </section>

              {/* 4. Handoff */}
              <section className="space-y-1.5">
                <p className={label}>4 · Handoff to Tier-2</p>
                {([
                  ["done", "What I already did", "Blocked the domain on the proxy, confirmed the user didn't report it"],
                  ["open", "What's still open", "Did it spread to other hosts? Activity after the last step?"],
                  ["next", "Recommended next step", "Isolate the host, reset the account, hunt the hash"],
                ] as const).map(([k, l, ph]) => (
                  <div key={k}>
                    <p id={`ir-${k}-label`} className="mb-0.5 text-[10px] text-slate-400">{l}</p>
                    <textarea aria-labelledby={`ir-${k}-label`} rows={2} value={report[k]} onChange={e => set({ [k]: e.target.value })} placeholder={ph} className={cn(field, "resize-none leading-relaxed")} />
                  </div>
                ))}
              </section>

              <p className="text-[10px] text-slate-500">Saved as you type: safe to close and come back.</p>
              <div className="flex items-center justify-between pt-1">
                <button type="button" onClick={onClose} className="text-xs text-slate-400 hover:text-slate-300 transition">
                  Close
                </button>
                <button
                  onClick={handleSubmit}
                  disabled={!canSubmit}
                  title={canSubmit ? undefined : "Add at least one timeline step and write the summary"}
                  className={cn(
                    "flex items-center gap-2 rounded border px-4 py-2 text-xs font-bold transition",
                    canSubmit
                      ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300 hover:bg-cyber-500/20"
                      : "border-border/40 text-slate-400 cursor-not-allowed opacity-50"
                  )}
                >
                  <FileText className="h-3.5 w-3.5" /> Escalate to Tier-2
                </button>
              </div>
            </>
          )}

          {/* ── GRADING phase ── */}
          {phase === "grading" && (
            <div className="py-8 flex flex-col items-center gap-5" role="status">
              <Loader2 aria-hidden="true" className="h-8 w-8 text-cyber-300 animate-spin" />
              <div className="text-center space-y-1">
                <p className="text-sm font-semibold text-white">Grading your report…</p>
                <p className="text-[11px] text-slate-400">Matching every timeline step to the attack&apos;s logs</p>
              </div>
            </div>
          )}

          {/* ── RESULT phase ── */}
          {phase === "result" && result && (
            <div className="space-y-4">
              {/* R-04 / QA-DASH-15: the deterministic grader is what runs when no AI
                  key is configured (production today), so say plainly what it checks.
                  No "full review pending": there is no later review that changes it. */}
              {result.graded_by === "deterministic" && result.mode !== "timeline" && (
                <div className="rounded-lg border border-neon-amber/30 bg-neon-amber/5 px-4 py-2.5 flex items-start gap-2">
                  <AlertTriangle className="h-4 w-4 text-neon-amber mt-0.5 shrink-0" />
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    <span className="font-bold text-neon-amber">Automated check.</span>{" "}
                    This score comes from an automated structural check: real vs. unverified
                    indicators, and whether you named a response action. It does <em>not</em> read
                    your reasoning, so structure, causality and business impact aren&apos;t scored
                    here.
                  </p>
                </div>
              )}
              {/* Score + pass/fail header */}
              <div ref={resultRef} tabIndex={-1} className={cn(
                "rounded-lg border p-4 flex items-center gap-5",
                passed
                  ? "border-neon-green/30 bg-neon-green/5"
                  : "border-severity-critical/30 bg-severity-critical/5"
              )}>
                <ScoreRing score={result.score} />
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    {passed
                      ? <CheckCircle2 className="h-4 w-4 text-neon-green shrink-0" />
                      : <AlertTriangle className="h-4 w-4 text-severity-critical shrink-0" />
                    }
                    <span className={cn("text-sm font-bold", passed ? "text-neon-green" : "text-severity-critical")}>
                      {passed ? "Escalation accepted" : "Not ready for Tier-2"}
                    </span>
                  </div>
                  <p className="text-[10px] text-slate-400">
                    {diffLabel} · pass mark {result.threshold ?? rule.score}/100 plus the {diffLabel} requirements</p>
                  <p className="text-[10px] text-slate-400">
                    {passed ? "You met all of them." : "Fix what's listed below and escalate again."}
                  </p>
                </div>
              </div>

              {/* Feedback */}
              <div className="rounded border border-border/40 bg-bg px-4 py-3 space-y-3">
                <p className="text-xs text-slate-200 leading-relaxed">{result.feedback}</p>

                {result.mode === "timeline" && result.requirements && result.requirements.length > 0 && (
                  <div className="rounded border border-severity-high/30 bg-severity-high/5 px-3 py-2">
                    <p className="mb-1 text-[9px] font-bold uppercase tracking-wider text-severity-high">To pass at {diffLabel}</p>
                    <ul className="space-y-0.5">
                      {result.requirements.map((r, i) => <li key={i} className="text-[11px] text-slate-200">· {r}</li>)}
                    </ul>
                  </div>
                )}
                {result.mode === "timeline" && result.checks ? (
                  <ul className="divide-y divide-border/40">
                    {result.checks.map((c, i) => (
                      <li key={i} className="flex items-start gap-2 py-2">
                        {c.status === "ok" ? <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-neon-green" aria-label="Done" />
                          : c.status === "warn" ? <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-neon-amber" aria-label="Improve" />
                          : <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-severity-high" aria-label="Missing" />}
                        <span className="text-[11px] leading-relaxed text-slate-300">
                          <span className="font-semibold text-slate-100">{c.title}</span>{c.detail ? <> {c.detail}</> : null}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : <>
                {result.strengths.length > 0 && (
                  <div>
                    <p className="text-[9px] font-bold uppercase tracking-wider text-neon-green mb-1">Strengths</p>
                    {result.strengths.map((s, i) => (
                      <p key={i} className="text-[10px] text-slate-300 flex items-start gap-1.5">
                        <CheckCircle2 className="h-3 w-3 text-neon-green mt-0.5 shrink-0" />{s}
                      </p>
                    ))}
                  </div>
                )}

                {result.gaps.length > 0 && (
                  <div>
                    <p className="text-[9px] font-bold uppercase tracking-wider text-neon-amber mb-1">To Improve</p>
                    {result.gaps.map((g, i) => (
                      <p key={i} className="text-[10px] text-slate-300 flex items-start gap-1.5">
                        <AlertTriangle className="h-3 w-3 text-neon-amber mt-0.5 shrink-0" />{g}
                      </p>
                    ))}
                  </div>
                )}
                </>}
              </div>

              {/* Response-time coaching — a gentle pace note, NEVER part of the
                  grade. Within target → a positive note; over target → a soft
                  "areas to improve" nudge. The live feed is practice, so time is
                  only ever coaching (see useLiveEvents: no miss, no penalty). */}
              {responseMs != null && (() => {
                const targetMs  = responseTargetSeconds * 1000;
                const within    = responseMs <= targetMs;
                const targetMin = Math.round(responseTargetSeconds / 60);
                const overBy    = fmtDuration(responseMs - targetMs);
                return (
                  <div className={cn(
                    "rounded border px-4 py-3 space-y-1.5",
                    within ? "border-neon-green/25 bg-neon-green/5" : "border-neon-amber/25 bg-neon-amber/5"
                  )}>
                    <div className="flex items-center gap-1.5">
                      {within
                        ? <CheckCircle2 className="h-3.5 w-3.5 text-neon-green shrink-0" />
                        : <AlertTriangle className="h-3.5 w-3.5 text-neon-amber shrink-0" />}
                      <p className={cn(
                        "text-[10px] font-bold uppercase tracking-wider",
                        within ? "text-neon-green" : "text-neon-amber"
                      )}>
                        {within ? "Response time" : "Areas to improve"}
                      </p>
                    </div>
                    <p className="text-xs font-semibold text-slate-200">
                      Response time: {fmtDuration(responseMs)}
                    </p>
                    <p className={cn("text-[10px] leading-relaxed", within ? "text-neon-green" : "text-neon-amber")}>
                      {within
                        ? `Good pace — within the ${targetMin}-minute response target.`
                        : `Response time exceeded the ${targetMin}-minute target by ${overBy} — work on faster triage next shift.`}
                    </p>
                    <p className="text-[9px] text-slate-500">Coaching only — this does not affect your score.</p>
                  </div>
                );
              })()}

              {/* Decoy debrief — only after a PASS. Recognising false positives is
                  half of SOC work; these benign events looked suspicious this
                  session, and this is the context that clears each one. Withheld
                  on a failed report so it can't be used to deduce the real attack
                  by elimination before a resubmit. */}
              {passed && decoys.length > 0 && (
                <div className="rounded border border-cyber-500/25 bg-cyber-500/5 px-4 py-3 space-y-2">
                  <div className="flex items-center gap-1.5">
                    <Shield className="h-3.5 w-3.5 text-cyber-300 shrink-0" />
                    <p className="text-[10px] font-bold uppercase tracking-wider text-cyber-300">
                      False Positives You Saw — Why They Were Benign
                    </p>
                  </div>
                  <p className="text-[10px] text-slate-400 leading-relaxed">
                    Not every alarming log is an attack. These events looked suspicious but were
                    legitimate — clearing them correctly is as important as catching the real intrusion.
                  </p>
                  <div className="space-y-1.5 pt-0.5">
                    {decoys.map((d, i) => (
                      <div key={i} className="rounded border border-border/30 bg-bg px-2.5 py-2">
                        <div className="flex items-center gap-1.5 mb-1">
                          <span className="inline-flex items-center rounded border border-slate-500/30 bg-slate-500/10 px-1.5 py-0.5 text-[8px] font-semibold uppercase tracking-wider text-slate-300">
                            {d.source.replace(/_/g, " ")}
                          </span>
                          <span className="text-[10px] font-medium text-slate-200">{d.label}</span>
                        </div>
                        <p className="text-[10px] text-slate-400 leading-relaxed">{d.fp_explanation}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Action buttons */}
              <div className="space-y-2">
                {passed && credited && (
                  <div className="rounded border border-neon-green/30 bg-neon-green/5 px-4 py-2.5 flex items-center gap-2">
                    <Shield className="h-4 w-4 text-neon-green shrink-0" />
                    <p className="text-[11px] text-neon-green font-semibold">
                      Incident closed and credited to your shift. Catches count toward securing {companyName} automatically.
                    </p>
                  </div>
                )}
                {passed && !credited && (
                  <div className="rounded border border-border/50 bg-bg/40 px-4 py-2.5 flex items-center gap-2">
                    <Shield className="h-4 w-4 text-slate-400 shrink-0" />
                    <p className="text-[11px] text-slate-300">
                      No open incident to close right now, so nothing was credited. Keep monitoring the feed.
                    </p>
                  </div>
                )}

                {!passed && (
                  <button
                    onClick={() => { setPhase("form"); setResult(null); }}
                    className="w-full rounded border border-neon-amber/40 bg-neon-amber/8 py-2 text-xs font-bold text-neon-amber hover:bg-neon-amber/15 transition"
                  >
                    Revise the report
                  </button>
                )}

                <button
                  onClick={onClose}
                  className="w-full rounded border border-cyber-500/40 bg-cyber-500/10 py-2.5 text-xs font-bold text-cyber-300 hover:bg-cyber-500/20 transition"
                >
                  {passed ? "Close & Continue Monitoring" : "Close — Keep Monitoring"}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
