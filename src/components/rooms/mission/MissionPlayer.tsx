"use client";
/**
 * The mission screen (SPEC section 3): case bar with the step chain, the
 * briefing, the workbench of the current step, and the case notebook beside it.
 *
 * Each step is checked on its own by the server (per-step attempts and XP).
 * Help ladder per step: Hint, then Where to look (60% XP), then after three
 * wrong checks the worked answer and a way to move on (0 XP, the case goes on).
 * No timers, no lives.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { CheckCircle2, ChevronRight, Lightbulb, MapPin, BookOpenCheck, Lock, CircleDot, Send, Briefcase } from "lucide-react";
import { ApiError, userMessageFor } from "@/lib/http/apiError";
import type { SanitizedMissionTask, SanitizedStep } from "@/lib/missions/sanitize";
import { WORKED_AFTER_MISSES } from "@/lib/missions/types";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/Button";
import { InlineMd } from "../InlineMd";
import type { ReviewRecord } from "../reviewStore";
import { KqlBench } from "./KqlBench";
import { ArtifactView, FieldsBench, ReportBench, RuleBench, StringsBench } from "./Benches";
import { Notebook } from "./Notebook";
import { loadMissionState, newId, saveMissionState, useNotebook } from "./notebookStore";
import { useMissionDataset } from "./useDataset";

type Submit = (roomId: string, taskId: string, body: unknown) => Promise<{ correct: boolean; xpEarned: number; reveal: Record<string, unknown> }>;

interface Draft { query?: string; values?: Record<string, string>; picks?: string[]; source?: string; slots?: Record<string, string> }
interface StepState {
  status: "open" | "passed" | "worked";
  misses: number;
  hints: number;
  xp: number;
  draft: Draft;
  feedback?: string[];
  reveal?: Record<string, unknown>;
}

const fresh = (s: SanitizedStep): StepState => ({
  status: "open", misses: 0, hints: 0, xp: 0,
  draft: s.kind === "kql" ? { query: s.starter ?? "" } : s.kind === "rule" ? { source: s.starter } : {},
});

/** Worked answers and debriefs: prose with `inline code`, plus fenced code blocks for full queries and rules. */
function Md({ text }: { text: string }) {
  const parts = text.split(/```[a-z]*\n?/);
  return (
    <div className="space-y-2">
      {parts.map((p, i) => i % 2 === 1
        ? <pre key={i} className="overflow-x-auto rounded-md border border-border bg-[#0b1220] px-3 py-2 font-mono text-[12px] leading-5 text-slate-100">{p.replace(/\n$/, "")}</pre>
        : p.trim() ? <p key={i} className="whitespace-pre-wrap"><InlineMd text={p.trim()} /></p> : null)}
    </div>
  );
}

const KIND_LABEL: Record<SanitizedStep["kind"], string> = {
  kql: "Query", fields: "Evidence form", iocs: "Collect indicators", strings: "Strings", rule: "Rule", report: "Finding",
};

export function MissionPlayer({ roomId, task, onComplete, isCompleted, onRecord, submit }: {
  roomId: string;
  task: SanitizedMissionTask;
  onComplete: (xp: number, passCredit?: number) => void;
  isCompleted: boolean;
  onRecord: (r: ReviewRecord) => void;
  submit: Submit;
}) {
  const [states, setStates] = useState<StepState[]>(() => task.steps.map(fresh));
  const [active, setActive] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { nb, update } = useNotebook(roomId);
  // The notebook sits beside the workbench only when the mission has the width for both
  // (the Operation view's study guide can take half the screen); otherwise it goes below.
  const shell = useRef<HTMLDivElement>(null);
  const [wide, setWide] = useState(false);
  useEffect(() => {
    const el = shell.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(([e]) => setWide(e.contentRect.width >= 920));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  const dataset = useMissionDataset(task.dataset);

  // Restore this device's progress on the mission (drafts and passed steps).
  useEffect(() => {
    const saved = loadMissionState<StepState[]>(roomId, task.id);
    if (saved && saved.length === task.steps.length) {
      setStates(saved);
      const firstOpen = saved.findIndex(s => s.status === "open");
      setActive(firstOpen === -1 ? saved.length - 1 : firstOpen);
    }
  }, [roomId, task.id, task.steps.length]);
  useEffect(() => { saveMissionState(roomId, task.id, states); }, [roomId, task.id, states]);

  const done = states.every(s => s.status !== "open");
  const totalXp = states.reduce((a, s) => a + s.xp, 0);
  const passCredit = task.steps.reduce((a, s, i) => a + (states[i].status === "passed" ? s.xp : 0), 0);
  const maxXp = task.steps.reduce((a, s) => a + s.xp, 0);
  const unlocked = (i: number) => i === 0 || states.slice(0, i).every(s => s.status !== "open");

  const step = task.steps[active];
  const st = states[active];
  const setSt = (fn: (s: StepState) => StepState) => setStates(all => all.map((s, i) => (i === active ? fn(s) : s)));
  const setDraft = (d: Partial<Draft>) => setSt(s => ({ ...s, draft: { ...s.draft, ...d } }));

  const record = (next: StepState[]) => onRecord({
    type: "mission",
    steps: task.steps.map((s, i) => ({
      id: s.id, kind: s.kind, status: next[i].status, xp: next[i].xp,
      worked: typeof next[i].reveal?.worked === "string" ? next[i].reveal!.worked as string : undefined,
      debrief: typeof next[i].reveal?.debrief === "string" ? next[i].reveal!.debrief as string : undefined,
    })),
  });

  function answerFor(s: SanitizedStep, d: Draft): unknown {
    switch (s.kind) {
      case "kql": return { query: d.query ?? "" };
      case "fields": return { values: d.values ?? {} };
      case "iocs": return { iocs: nb.iocs.map(i => ({ type: i.type, value: i.value })) };
      case "strings": return { picks: d.picks ?? [] };
      case "rule": return { source: d.source ?? "" };
      case "report": return { slots: d.slots ?? {} };
    }
  }

  async function check() {
    setBusy(true); setError(null);
    try {
      const res = await submit(roomId, task.id, {
        stepIndex: active, answer: answerFor(step, st.draft), hintsUsed: st.hints, attemptNumber: st.misses + 1,
      });
      const fb = Array.isArray(res.reveal.feedback) ? res.reveal.feedback as string[] : [];
      const next = states.map((s, i) => i !== active ? s : {
        ...s,
        status: res.correct ? "passed" as const : s.status,
        misses: res.correct ? s.misses : s.misses + 1,
        xp: res.correct ? Math.max(s.xp, res.xpEarned) : s.xp,
        feedback: fb,
        reveal: res.reveal,
      });
      setStates(next);
      record(next);
    } catch (e) {
      // A query that does not run or an empty answer: shown here, and it was not counted as a check.
      setError(e instanceof ApiError ? e.message : userMessageFor(e));
    } finally {
      setBusy(false);
    }
  }

  function moveOn() {
    const next = states.map((s, i) => (i === active ? { ...s, status: "worked" as const } : s));
    setStates(next);
    record(next);
    if (active < task.steps.length - 1) setActive(active + 1);
  }

  function pin(source: string, text: string, time?: string) {
    update(n => n.pins.some(p => p.text === text) ? n : { ...n, pins: [...n.pins, { id: newId(), source, text, time }] });
  }

  const artifacts = useMemo(() => new Map((task.artifacts ?? []).map(a => [a.id, a])), [task.artifacts]);

  if (isCompleted) {
    return (
      <div className="space-y-4">
        <h2 className="text-xl font-bold text-white">{task.heading}</h2>
        <div className="inline-flex items-center gap-2 rounded border border-neon-green/40 bg-neon-green/10 px-3 py-1.5 text-sm text-neon-green">
          <CheckCircle2 className="h-4 w-4" /> Mission completed
        </div>
        <p className="text-sm text-slate-400"><InlineMd text={task.objective} /></p>
        <Button variant="primary" size="md" onClick={() => onComplete(0)}>Next Task <ChevronRight className="h-4 w-4" /></Button>
      </div>
    );
  }

  const reveal = st.reveal ?? {};
  const workedOut = st.misses >= WORKED_AFTER_MISSES;
  const fieldVerdicts = Array.isArray(reveal.fields) ? reveal.fields as { id: string; ok: boolean; say?: string }[] : undefined;
  const slotVerdicts = Array.isArray(reveal.slots) ? reveal.slots as { id: string; ok: boolean; missing: string[]; flagged: string[]; tooLong: boolean; words: number }[] : undefined;
  const pickVerdicts = Array.isArray(reveal.picks) ? reveal.picks as { value: string; ok: boolean; good: number; bad: number; inSample: boolean }[] : undefined;
  const iocVerdict = reveal.iocs as { found: number; total: number; missing: string[]; flagged: { value: string; say: string }[] } | undefined;
  const ruleVerdict = reveal.rule as { visibleWrong: string[]; hiddenMissed: { name: string; note?: string }[]; hiddenFalse: { name: string; note?: string }[]; hiddenTotal: number } | undefined;
  const ready = (() => {
    const d = st.draft;
    switch (step.kind) {
      case "kql": return !!d.query?.trim();
      case "fields": return step.fields.some(f => d.values?.[f.id]?.trim());
      case "iocs": return nb.iocs.length > 0;
      case "strings": return (d.picks?.length ?? 0) > 0;
      case "rule": return !!d.source?.trim();
      case "report": return step.slots.some(s => d.slots?.[s.id]?.trim());
    }
  })();

  return (
    <div ref={shell} className="space-y-4">
      {/* Case bar: where this mission sits in the room's story, and its step chain. */}
      <div className="rounded-xl border border-cyber-500/30 bg-gradient-to-r from-cyber-500/10 to-transparent px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <Briefcase className="h-4 w-4 text-cyber-300" aria-hidden />
          <h2 className="text-lg font-bold text-white">{task.heading}</h2>
          <span className="ml-auto font-mono text-xs text-slate-400">{totalXp}/{maxXp} XP</span>
        </div>
        <ol className="mt-2 flex flex-wrap gap-1.5" aria-label="Mission steps">
          {task.steps.map((s, i) => {
            const state = states[i].status;
            const open = unlocked(i);
            return (
              <li key={s.id}>
                <button type="button" disabled={!open} onClick={() => { setActive(i); setError(null); }} aria-current={i === active ? "step" : undefined}
                  className={cn("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs",
                    i === active ? "border-cyber-400 bg-cyber-500/20 text-white" : "border-border text-slate-400 hover:text-slate-200",
                    !open && "cursor-not-allowed opacity-50")}>
                  {state === "passed" ? <CheckCircle2 className="h-3.5 w-3.5 text-neon-green" aria-hidden />
                    : state === "worked" ? <BookOpenCheck className="h-3.5 w-3.5 text-neon-amber" aria-hidden />
                    : open ? <CircleDot className="h-3.5 w-3.5" aria-hidden /> : <Lock className="h-3.5 w-3.5" aria-hidden />}
                  {i + 1}. {KIND_LABEL[s.kind]}
                  <span className="sr-only">{state === "passed" ? " (done)" : state === "worked" ? " (worked answer used)" : open ? "" : " (locked)"}</span>
                </button>
              </li>
            );
          })}
        </ol>
      </div>

      <div className={cn("grid gap-4", wide && "grid-cols-[minmax(0,1fr)_18rem]")}>
        <div className="min-w-0 space-y-4">
          {/* Briefing */}
          <section aria-label="Briefing" className="space-y-2 rounded-xl border border-border bg-bg-panel/60 p-4">
            {task.mentor && <p className="text-[11px] font-semibold uppercase tracking-wider text-cyber-300">{task.mentor}</p>}
            <p className="text-sm leading-relaxed text-slate-300"><InlineMd text={task.story} /></p>
            <p className="text-sm font-medium text-white"><span className="text-slate-400">Deliverable: </span><InlineMd text={task.objective} /></p>
          </section>

          {/* Workbench of the current step */}
          <section aria-label={`Step ${active + 1}`} className="space-y-3 rounded-xl border border-border bg-bg-panel/40 p-4">
            <div className="flex flex-wrap items-baseline gap-2">
              <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-400">Step {active + 1}: {KIND_LABEL[step.kind]}</h3>
              <span className="text-xs text-slate-500">{step.xp} XP</span>
            </div>
            <p className="text-sm leading-relaxed text-white"><InlineMd text={step.prompt} /></p>

            {"artifactIds" in step && step.artifactIds && step.artifactIds.length > 0 && (
              <div className="space-y-2">
                {step.artifactIds.map(id => artifacts.get(id)).filter(Boolean).map(a => (
                  <ArtifactView key={a!.id} roomId={roomId} artifact={a!} collect={step.kind === "iocs"} />
                ))}
              </div>
            )}

            {step.kind === "kql" && (
              dataset.data
                ? <KqlBench key={step.id} data={dataset.data} focusTables={step.focusTables} query={st.draft.query ?? ""} onQuery={q => setDraft({ query: q })} onPin={pin} disabled={busy} />
                : dataset.error
                  ? <p className="text-sm text-neon-amber">{dataset.error} <button type="button" className="underline" onClick={dataset.retry}>Try again</button></p>
                  : <p className="text-sm text-slate-400">Loading the case data...</p>
            )}
            {step.kind === "fields" && (
              <FieldsBench fields={step.fields} values={st.draft.values ?? {}} onChange={v => setDraft({ values: v })} verdicts={fieldVerdicts} disabled={busy || st.status !== "open"} />
            )}
            {step.kind === "fields" && dataset.data && (
              // The workspace stays open on form steps: facts come from queries, not from memory.
              <details className="rounded-lg border border-border bg-bg-panel/40 p-3">
                <summary className="cursor-pointer text-sm font-semibold text-slate-200">Query the workspace (not graded)</summary>
                <div className="mt-3">
                  <KqlBench key={`${step.id}-scratch`} data={dataset.data} query={st.draft.query ?? ""} onQuery={q => setDraft({ query: q })} onPin={pin} disabled={busy} />
                </div>
              </details>
            )}
            {step.kind === "iocs" && (
              <p className="rounded-md border border-border bg-bg-elevated/60 px-3 py-2 text-xs text-slate-300">
                Your notebook holds {nb.iocs.length} indicator{nb.iocs.length === 1 ? "" : "s"}. The check reads the notebook as it is now: add what belongs to the attacker, remove what does not.
              </p>
            )}
            {step.kind === "strings" && (
              <StringsBench view={step.view} totals={step.totals} picks={st.draft.picks ?? []} onPicks={p => setDraft({ picks: p })} verdicts={pickVerdicts} disabled={busy || st.status !== "open"} />
            )}
            {step.kind === "rule" && (
              <RuleBench key={step.id} language={step.language} source={st.draft.source ?? ""} onSource={s => setDraft({ source: s })} samples={task.samples} events={task.events} hiddenCount={step.hiddenCount} disabled={busy} />
            )}
            {step.kind === "report" && (
              <ReportBench slots={step.slots} values={st.draft.slots ?? {}} onChange={v => setDraft({ slots: v })} verdicts={slotVerdicts} disabled={busy || st.status !== "open"} />
            )}

            {/* Help ladder */}
            {st.status === "open" && (
              <div className="space-y-2">
                <div className="flex flex-wrap gap-2">
                  <button type="button" onClick={() => setSt(s => ({ ...s, hints: Math.max(s.hints, 1) }))} disabled={st.hints >= 1}
                    className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-slate-300 hover:border-neon-amber/50 hover:text-neon-amber disabled:opacity-60">
                    <Lightbulb className="h-3.5 w-3.5" aria-hidden /> Hint
                  </button>
                  {st.hints >= 1 && (
                    <button type="button" onClick={() => setSt(s => ({ ...s, hints: 2 }))} disabled={st.hints >= 2}
                      className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-slate-300 hover:border-neon-amber/50 hover:text-neon-amber disabled:opacity-60">
                      <MapPin className="h-3.5 w-3.5" aria-hidden /> Where to look <span className="text-slate-500">(step pays 60%)</span>
                    </button>
                  )}
                </div>
                {st.hints >= 1 && <p className="rounded-md border border-neon-amber/30 bg-neon-amber/5 px-3 py-2 text-xs text-slate-200"><InlineMd text={step.hint} /></p>}
                {st.hints >= 2 && <p className="rounded-md border border-neon-amber/30 bg-neon-amber/5 px-3 py-2 text-xs text-slate-200"><InlineMd text={step.where} /></p>}
              </div>
            )}

            {error && <p role="alert" className="rounded-md border border-neon-amber/40 bg-neon-amber/10 px-3 py-2 text-sm text-neon-amber">{error}</p>}

            {/* Feedback on the last check */}
            <div aria-live="polite" className="space-y-2">
              {st.status === "open" && st.misses > 0 && (
                <div className="space-y-1 rounded-lg border border-neon-amber/40 bg-neon-amber/10 p-3 text-sm">
                  <p className="font-semibold text-neon-amber">
                    {workedOut
                      ? "Not yet. The worked answer is below: read why it works, then check it (no XP) or move on."
                      : `Not yet. Check ${st.misses} of ${WORKED_AFTER_MISSES} before the worked answer.`}
                  </p>
                  {(st.feedback ?? []).map((f, i) => <p key={i} className="text-slate-200"><InlineMd text={f} /></p>)}
                  {iocVerdict && (
                    <>
                      <p className="text-slate-200">{iocVerdict.found} of {iocVerdict.total} attacker indicators are in your notebook.</p>
                      {iocVerdict.missing.length > 0 && st.hints >= 2 && <p className="text-slate-300">Still missing: {iocVerdict.missing.join(", ")}.</p>}
                      {iocVerdict.flagged.map(f => <p key={f.value} className="text-severity-high"><span className="font-mono">{f.value}</span>: {f.say}</p>)}
                    </>
                  )}
                  {pickVerdicts && <p className="text-slate-200">{pickVerdicts.filter(p => p.ok).length} of your picks are stable and unique; you need {String(reveal.need)} and no weak ones. Red rows appear in goodware or in too few builds.</p>}
                  {ruleVerdict && (
                    <ul className="list-inside list-disc text-slate-200">
                      {ruleVerdict.visibleWrong.length > 0 && <li>Wrong on the test set: {ruleVerdict.visibleWrong.join(", ")}. Run it and read the table.</li>}
                      {ruleVerdict.hiddenMissed.map(h => <li key={h.name}>Missed a hidden malicious file{h.note ? `: ${h.note}` : ""}.</li>)}
                      {ruleVerdict.hiddenFalse.map(h => <li key={h.name}>Matched a hidden clean file{h.note ? `: ${h.note}` : ""}.</li>)}
                    </ul>
                  )}
                </div>
              )}
              {st.status === "passed" && (
                <div className="space-y-1 rounded-lg border border-neon-green/40 bg-neon-green/10 p-3 text-sm">
                  <p className="font-semibold text-neon-green">Step done. +{st.xp} XP</p>
                  {typeof reveal.debrief === "string" && <p className="text-slate-200"><InlineMd text={reveal.debrief} /></p>}
                </div>
              )}
              {(st.status !== "open" || workedOut) && typeof reveal.worked === "string" && (
                <details className="rounded-lg border border-border bg-bg-elevated/60 p-3 text-sm" open={st.status === "open"}>
                  <summary className="cursor-pointer font-semibold text-slate-200">{st.status === "passed" ? "Compare with the worked answer" : "Worked answer"}</summary>
                  <div className="mt-2 text-slate-300"><Md text={reveal.worked} /></div>
                  {st.status === "open" && typeof reveal.debrief === "string" && <p className="mt-2 text-slate-400"><InlineMd text={reveal.debrief} /></p>}
                </details>
              )}
            </div>

            <div className="flex flex-wrap gap-2">
              {st.status === "open" && (
                <Button variant="primary" size="md" disabled={!ready || busy} onClick={check}>
                  <Send className="h-4 w-4" /> {busy ? "Checking..." : "Check"}
                </Button>
              )}
              {st.status === "open" && workedOut && (
                <Button variant="secondary" size="md" onClick={moveOn}>Move on without the XP <ChevronRight className="h-4 w-4" /></Button>
              )}
              {st.status !== "open" && active < task.steps.length - 1 && (
                <Button variant="primary" size="md" onClick={() => { setActive(active + 1); setError(null); }}>Next step <ChevronRight className="h-4 w-4" /></Button>
              )}
            </div>
          </section>

          {done && (
            <div className="space-y-2 rounded-xl border border-neon-green/40 bg-neon-green/10 p-4">
              <p className="font-semibold text-neon-green">Mission complete: {totalXp}/{maxXp} XP</p>
              <Button variant="primary" size="md" onClick={() => onComplete(totalXp, passCredit)}>Next <ChevronRight className="h-4 w-4" /></Button>
            </div>
          )}
        </div>

        <Notebook roomId={roomId} />
      </div>
    </div>
  );
}
