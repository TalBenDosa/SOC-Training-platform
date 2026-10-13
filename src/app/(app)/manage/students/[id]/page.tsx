"use client";
/**
 * Per-student drill-down (org-admin / instructor). Four tabs answer, in order:
 *  - Summary: how they are doing, where they are strong and weak (first-try accuracy by
 *    room topic), and which rooms hold most of their mistakes;
 *  - Mistakes: every question not right on the first try, grouped by room, shown as the
 *    question, their first answer, the right answer, the explanation and the tries it took;
 *  - Activity: scenarios (with the report they submitted), rooms and live-feed sessions;
 *  - Plan: the personal learning plan.
 *
 * Data + org-scoping come from GET /api/org/students/[id] (requireOrgAdmin; the student is
 * verified to be in the caller's org server-side; answers are resolved there, never here).
 */
import { useEffect, useMemo, useState } from "react";
import { useParams, useSearchParams } from "next/navigation";
import Link from "next/link";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import {
  ArrowLeft, Loader2, AlertTriangle, DoorOpen, Target, Activity, Timer, Clock, KeyRound, CalendarDays, Gauge,
  XCircle, CheckCircle2, Crosshair, ListChecks, ClipboardList, ExternalLink, Info,
} from "lucide-react";
import type { StudentDetail } from "@/app/api/org/students/[id]/route";
import { PersonalPrioritiesCard } from "@/components/manage/PersonalPrioritiesCard";
import { cn } from "@/lib/utils";

type Tab = "summary" | "mistakes" | "activity" | "plan";
const MIN_ITEMS = 5; // fewer gradable questions than this in a topic is not enough to judge it

function fmtMs(ms: number | null): string {
  if (ms === null) return "n/a";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}
function fmtSecs(sec: number | null): string {
  if (sec === null) return "n/a";
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`;
}
function fmtDate(iso: string | null): string {
  if (!iso) return "n/a";
  return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "2-digit", hour: "2-digit", minute: "2-digit" });
}
/** Strong / developing / weak by first-try accuracy; "not enough" under MIN_ITEMS questions. */
function level(accuracy: number | null, items: number): { label: string; bar: string; text: string } {
  if (accuracy === null || items < MIN_ITEMS) return { label: "Not enough answers yet", bar: "bg-slate-600", text: "text-slate-400" };
  if (accuracy >= 80) return { label: "Strong", bar: "bg-neon-green", text: "text-neon-green" };
  if (accuracy >= 60) return { label: "Developing", bar: "bg-neon-amber", text: "text-neon-amber" };
  return { label: "Weak", bar: "bg-severity-high", text: "text-severity-high" };
}
const VERDICT_LABEL: Record<string, string> = { true_positive: "True positive", false_positive: "False positive", escalate: "Escalate", benign: "Benign", malicious: "Malicious" };

export default function StudentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<StudentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // ?tab=mistakes opens straight on a tab (the class heatmap links here).
  const initialTab = useSearchParams()?.get("tab");
  const [tab, setTab] = useState<Tab>(initialTab === "mistakes" || initialTab === "activity" || initialTab === "plan" ? initialTab : "summary");
  const [onlyUnsolved, setOnlyUnsolved] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/org/students/${id}`)
      .then(async r => (r.ok ? r.json() : Promise.reject((await r.json().catch(() => ({})))?.error ?? "Failed to load.")))
      .then(d => { if (!cancelled) { setData(d); setLoading(false); } })
      .catch(e => { if (!cancelled) { setError(typeof e === "string" ? e : "Couldn't reach the server. Check your connection and reload."); setLoading(false); } });
    return () => { cancelled = true; };
  }, [id]);

  const name = data?.display_name || data?.handle || (data ? data.user_id.slice(0, 8) : "Student");
  const affDays = data?.affiliation_expires_at ? Math.ceil((Date.parse(data.affiliation_expires_at) - Date.now()) / 86_400_000) : null;
  const mistakeCount = useMemo(() => (data?.mistake_groups ?? []).reduce((n, g) => n + g.mistakes.length, 0), [data]);
  const judged = (data?.skills ?? []).filter(t => t.items >= MIN_ITEMS);
  const strong = judged.filter(t => (t.accuracy ?? 0) >= 80).sort((a, b) => (b.accuracy ?? 0) - (a.accuracy ?? 0));
  const weak = judged.filter(t => (t.accuracy ?? 100) < 60).sort((a, b) => (a.accuracy ?? 0) - (b.accuracy ?? 0));
  const answeredAreas = (data?.skills ?? []).filter(t => t.items > 0);

  return (
    <div>
      <Topbar title="Student" subtitle="Strengths, mistakes and activity" />
      <div className="container mx-auto max-w-[1000px] space-y-5 px-6 py-6">
        <Link href="/manage" className="inline-flex items-center gap-1.5 text-sm text-slate-400 transition hover:text-white">
          <ArrowLeft className="h-4 w-4" /> Back to the class
        </Link>

        {error && <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>}

        {loading ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : data ? (
          <>
            {/* Identity */}
            <Card>
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <h1 className="text-xl font-bold text-white"><bdi>{name}</bdi></h1>
                  <p className="mt-0.5 font-mono text-xs text-slate-400">{data.handle ? `@${data.handle} · ` : ""}{data.role} · {data.status}</p>
                  <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-400">
                    <span><CalendarDays className="mr-1 inline h-3 w-3" />joined {fmtDate(data.joined_at)}</span>
                    <span><Clock className="mr-1 inline h-3 w-3" />last active {fmtDate(data.last_active_at)}</span>
                    {affDays !== null && (
                      <span className={affDays < 0 ? "font-bold text-severity-high" : affDays <= 14 ? "text-neon-amber" : ""}>
                        <KeyRound className="mr-1 inline h-3 w-3" />{affDays < 0 ? "enrolment lapsed" : `enrolment ${affDays}d left`}
                      </span>
                    )}
                  </div>
                </div>
                <div className="text-right">
                  <p className="font-mono text-2xl font-bold text-cyber-300">{data.xp.toLocaleString()}<span className="ml-1 text-sm text-slate-400">XP</span></p>
                  <p className="text-[11px] text-slate-400">Level {data.level}</p>
                </div>
              </div>
            </Card>

            {/* Tabs */}
            <div role="tablist" aria-label="Student sections" className="flex flex-wrap gap-1 border-b border-border">
              {([
                ["summary", "Summary", Gauge, null],
                ["mistakes", "Mistakes", XCircle, mistakeCount],
                ["activity", "Activity", Activity, null],
                ["plan", "Plan", ListChecks, null],
              ] as const).map(([key, label, Icon, count]) => (
                <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}
                  className={cn("-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm transition",
                    tab === key ? "border-cyber-400 font-semibold text-white" : "border-transparent text-slate-400 hover:text-white")}>
                  <Icon className="h-4 w-4" aria-hidden="true" /> {label}
                  {count !== null && count > 0 && <span className="rounded bg-severity-high/15 px-1.5 font-mono text-[10px] text-severity-high">{count}</span>}
                </button>
              ))}
            </div>

            {/* ── Summary ─────────────────────────────────────────────── */}
            {tab === "summary" && (
              <div className="space-y-5">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
                  <Metric icon={<CheckCircle2 className="h-4 w-4" />} label="Right first try"
                    value={data.summary.first_try.accuracy === null ? "n/a" : `${data.summary.first_try.accuracy}%`}
                    hint={`${data.summary.first_try.firstTryCorrect} of ${data.summary.first_try.items} questions`}
                    tip="Share of room questions answered correctly on the first attempt. Retries and readings don't count, so it measures what the student knew, not how often they tried."
                    tone={level(data.summary.first_try.accuracy, data.summary.first_try.items).text} />
                  <Metric icon={<DoorOpen className="h-4 w-4" />} label="Rooms done" value={`${data.summary.rooms_completed}/${data.summary.rooms_started}`} hint="completed / started" />
                  <Metric icon={<Target className="h-4 w-4" />} label="Scenario score" value={data.summary.scenario_avg_score === null ? "n/a" : `${data.summary.scenario_avg_score}%`}
                    hint={`${data.summary.scenarios_completed} completed`} tone={data.summary.scenario_avg_score !== null && data.summary.scenario_avg_score < 60 ? "text-severity-high" : undefined} />
                  <Metric icon={<Crosshair className="h-4 w-4" />} label="Live feed detection" value={data.summary.avg_detect_rate === null ? "n/a" : `${data.summary.avg_detect_rate}%`}
                    hint={`${data.summary.sessions} shifts`} tip="Average share of attacks the student caught in the live SOC feed." />
                  <Metric icon={<Timer className="h-4 w-4" />} label="Median answer time" value={fmtMs(data.summary.median_decision_latency_ms)} hint={`${data.summary.tasks_answered} tasks timed`} />
                </div>

                <Card>
                  <h2 className="mb-3 text-sm font-bold text-white">Strengths and weak spots</h2>
                  {answeredAreas.length === 0 ? (
                    <p className="text-sm text-slate-400">No graded answers yet. Skill areas appear here once the student answers questions in rooms, quizzes, lessons or scenarios.</p>
                  ) : (
                    <div className="grid gap-5 md:grid-cols-[1fr_1.1fr]">
                      <div className="space-y-2 text-sm leading-relaxed">
                        <p><span className="font-semibold text-neon-green">Strong in: </span>
                          <span className="text-slate-300">{strong.length ? strong.slice(0, 3).map(t => `${t.label} (${t.accuracy}%)`).join(", ") : "nothing yet at 80% or more."}</span></p>
                        <p><span className="font-semibold text-severity-high">Weak in: </span>
                          <span className="text-slate-300">{weak.length ? weak.map(t => `${t.label} (${t.accuracy}%, ${t.items} questions)`).join(", ") : "no area below 60%."}</span></p>
                        {data.summary.first_try.unsolved > 0 && (
                          <p><span className="font-semibold text-neon-amber">Still unsolved: </span>
                            <span className="text-slate-300">{data.summary.first_try.unsolved} question{data.summary.first_try.unsolved === 1 ? "" : "s"} never answered correctly.</span></p>
                        )}
                        {data.recommendations.length > 0 && (
                          <div className="pt-1">
                            <p className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Recommended next · {data.recommendations[0].area_label}</p>
                            <div className="flex flex-wrap gap-1.5">
                              {data.recommendations.map(r => (
                                <a key={r.room_id} href={`/rooms/${r.room_id}`} target="_blank" rel="noopener noreferrer"
                                  className="rounded-lg border border-cyber-500/30 bg-cyber-500/5 px-2 py-1 text-xs text-cyber-300 hover:bg-cyber-500/10">
                                  {r.title} <span className="text-[10px] text-slate-500">· {r.difficulty}</span>
                                </a>
                              ))}
                            </div>
                            <p className="mt-1 text-[10px] text-slate-500">Rooms in the weakest area not completed yet. Add them in the Plan tab.</p>
                          </div>
                        )}
                        {data.mistake_groups.length > 0 && (
                          <div className="pt-1">
                            <p className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">Most mistakes in</p>
                            <ul className="space-y-1">
                              {data.mistake_groups.slice(0, 3).map(g => (
                                <li key={g.room_id}>
                                  <button onClick={() => setTab("mistakes")} className="text-left text-slate-200 hover:text-cyber-300 hover:underline">
                                    {g.room_title} <span className="text-slate-500">· {g.mistakes.length} of {g.items}</span>
                                  </button>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                      <div className="space-y-2">
                        <p className="text-[11px] uppercase tracking-wider text-slate-500">Right first try, by skill area</p>
                        {data.skills.map(t => {
                          const lv = level(t.accuracy, t.items);
                          const src = Object.entries(t.sources).filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`).join(", ");
                          return (
                            <div key={t.area} className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)_auto] items-center gap-2 text-xs"
                              title={t.items ? `${lv.label}: ${t.firstTryCorrect} of ${t.items} right first try (${src})` : "No answers in this area yet"}>
                              <span className={cn("truncate", t.items ? "text-slate-300" : "text-slate-600")}>{t.label}</span>
                              <div className="h-2 rounded bg-bg"><div className={cn("h-2 rounded", lv.bar)} style={{ width: `${t.accuracy ?? 0}%` }} /></div>
                              <span className={cn("w-16 text-right font-mono", t.items ? lv.text : "text-slate-600")}>{t.items === 0 ? "none" : t.items < MIN_ITEMS ? `n=${t.items}` : `${t.accuracy}%`}</span>
                            </div>
                          );
                        })}
                        <p className="pt-1 text-[10px] text-slate-500">Rooms, quizzes, lesson checks and scenario questions, first answer only. Green 80%+ · amber 60-79% · red under 60% · grey: fewer than {MIN_ITEMS} questions answered, not enough to judge.</p>
                      </div>
                    </div>
                  )}
                </Card>
              </div>
            )}

            {/* ── Mistakes ────────────────────────────────────────────── */}
            {tab === "mistakes" && (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm text-slate-400">Every room question not answered correctly on the first try, grouped by room. Rooms with the most mistakes come first.</p>
                  <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-slate-300">
                    <input id="only-unsolved" type="checkbox" checked={onlyUnsolved} onChange={e => setOnlyUnsolved(e.target.checked)} /> Only still unsolved
                  </label>
                </div>
                {data.mistake_groups.length === 0 ? (
                  <Card><p className="text-sm text-slate-400">{data.summary.first_try.items === 0 ? "No graded answers yet. Mistakes appear here as the student works through rooms." : "No mistakes: every question was right on the first try."}</p></Card>
                ) : data.mistake_groups.map(g => {
                  const list = onlyUnsolved ? g.mistakes.filter(m => !m.solved) : g.mistakes;
                  if (!list.length) return null;
                  return (
                    <Card key={g.room_id} className="space-y-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-sm font-bold text-white">{g.room_title}</h3>
                        {g.room_category && <span className="rounded-full border border-border px-2 py-0.5 text-[10px] text-slate-400">{g.room_category}</span>}
                        <span className="text-[11px] text-slate-500">{g.mistakes.length} mistake{g.mistakes.length === 1 ? "" : "s"} · right first try on {g.first_try_correct} of {g.items}</span>
                        <a href={`/rooms/${g.room_id}`} target="_blank" rel="noopener noreferrer" className="ml-auto inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-white">
                          Open room <ExternalLink className="h-3 w-3" aria-hidden="true" />
                        </a>
                      </div>
                      {list.map(m => (
                        <div key={m.key} className="rounded-lg border border-border bg-bg px-3 py-2.5">
                          <p className="text-[11px] text-slate-500">{m.task_position ?? "Task"} · {m.type_label}</p>
                          {m.prompt && <p className="mt-0.5 text-sm text-slate-200" dir="auto">{m.prompt}</p>}
                          <div className="mt-2 flex flex-wrap gap-1.5 text-[11px]">
                            {m.chosen && <span className="rounded border border-severity-high/40 bg-severity-high/10 px-2 py-0.5 text-severity-high" dir="auto">Answered: {m.chosen}</span>}
                            {m.correct && <span className="rounded border border-neon-green/40 bg-neon-green/10 px-2 py-0.5 text-neon-green" dir="auto">Correct: {m.correct}</span>}
                            <span className={cn("rounded border px-2 py-0.5", m.solved ? "border-border text-slate-400" : "border-neon-amber/40 bg-neon-amber/10 text-neon-amber")}>
                              {m.solved ? (m.tries_to_solve === 1 ? "Solved" : `Solved on try ${m.tries_to_solve}`) : `Not solved yet · ${m.tries} tr${m.tries === 1 ? "y" : "ies"}`}
                            </span>
                            {m.latency_ms !== null && <span className="rounded border border-border px-2 py-0.5 text-slate-400"><Timer className="mr-0.5 inline h-3 w-3" aria-hidden="true" />{fmtMs(m.latency_ms)}</span>}
                            <span className="px-1 py-0.5 text-slate-500">{fmtDate(m.last_at)}</span>
                          </div>
                          {m.explanation && (
                            <details className="mt-2 text-xs text-slate-400">
                              <summary className="cursor-pointer select-none text-slate-500 hover:text-slate-300">Why</summary>
                              <p className="mt-1 leading-relaxed" dir="auto">{m.explanation}</p>
                            </details>
                          )}
                        </div>
                      ))}
                    </Card>
                  );
                })}
              </div>
            )}

            {/* ── Activity ────────────────────────────────────────────── */}
            {tab === "activity" && (
              <div className="space-y-5">
                <Card>
                  <h2 className="mb-3 flex items-center gap-2 text-sm font-bold text-white"><Target className="h-4 w-4 text-cyber-300" /> Scenarios</h2>
                  {data.scenarios.length === 0 ? (
                    <p className="text-sm text-slate-400">No scenarios completed yet.</p>
                  ) : (
                    <div className="space-y-2">
                      {data.scenarios.map((s, i) => (
                        <details key={`${s.slug}-${i}`} className="rounded-lg border border-border bg-bg px-3 py-2">
                          <summary className="flex cursor-pointer list-none flex-wrap items-center gap-3 text-sm">
                            <span className="text-slate-200">{s.title}</span>
                            <span className={cn("font-mono", s.score !== null && s.score < 60 ? "text-severity-high" : "text-slate-200")}>{s.score === null ? "n/a" : `${s.score}%`}</span>
                            <span className="font-mono text-xs text-slate-400">{fmtSecs(s.time_taken)}</span>
                            {s.report && <span className="inline-flex items-center gap-1 text-[11px] text-cyber-300"><ClipboardList className="h-3 w-3" aria-hidden="true" /> report</span>}
                            <span className="ml-auto text-[11px] text-slate-500">{fmtDate(s.completed_at)}</span>
                          </summary>
                          {s.report ? (
                            <div className="mt-2 space-y-1 border-t border-border/60 pt-2 text-xs text-slate-300">
                              <p><span className="text-slate-500">Verdict: </span>{VERDICT_LABEL[s.report.verdict ?? ""] ?? s.report.verdict ?? "n/a"}
                                {typeof s.report.reportScore === "number" && <span className="text-slate-500"> · report score {s.report.reportScore}%</span>}
                                {typeof s.report.passed === "boolean" && <span className={s.report.passed ? "text-neon-green" : "text-severity-high"}> · {s.report.passed ? "passed" : "not passed"}</span>}</p>
                              {s.report.verdictReason && <p className="whitespace-pre-wrap leading-relaxed text-slate-400" dir="auto">{s.report.verdictReason}</p>}
                            </div>
                          ) : <p className="mt-2 border-t border-border/60 pt-2 text-xs text-slate-500">No written report saved for this run.</p>}
                        </details>
                      ))}
                    </div>
                  )}
                </Card>

                <Card>
                  <h2 className="mb-3 flex items-center gap-2 text-sm font-bold text-white"><DoorOpen className="h-4 w-4 text-cyber-300" /> Rooms</h2>
                  {data.rooms.length === 0 ? <p className="text-sm text-slate-400">No rooms started yet.</p> : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-sm">
                        <thead><tr className="border-b border-border text-[11px] uppercase tracking-wider text-slate-400">
                          <th className="py-2 pr-4 font-medium">Room</th><th className="py-2 pr-4 font-medium">Status</th><th className="py-2 pr-4 font-medium">Tasks done</th>
                          <th className="py-2 pr-4 font-medium">XP</th><th className="py-2 pr-4 font-medium" title="How long the student took to respond per task">Avg answer time</th><th className="py-2 font-medium">Last touched</th>
                        </tr></thead>
                        <tbody className="divide-y divide-border/60">
                          {data.rooms.map(r => (
                            <tr key={r.room_id}>
                              <td className="py-2 pr-4 text-slate-200">{r.title}</td>
                              <td className="py-2 pr-4"><span className={cn("rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider", r.completed ? "border-neon-green/30 bg-neon-green/10 text-neon-green" : "border-slate-600 bg-slate-800/60 text-slate-400")}>{r.completed ? "Done" : "In progress"}</span></td>
                              <td className="py-2 pr-4 font-mono text-slate-400">{r.tasks_done}</td>
                              <td className="py-2 pr-4 font-mono text-cyber-300">{r.xp_earned}</td>
                              <td className="py-2 pr-4 font-mono text-slate-400">{fmtMs(r.avg_decision_latency_ms)}</td>
                              <td className="py-2 text-[11px] text-slate-500">{fmtDate(r.updated_at)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </Card>

                <Card>
                  <h2 className="mb-3 flex items-center gap-2 text-sm font-bold text-white"><Crosshair className="h-4 w-4 text-cyber-300" /> Live SOC feed shifts</h2>
                  {data.sessions.length === 0 ? <p className="text-sm text-slate-400">No live feed shifts yet.</p> : (
                    <div className="flex flex-wrap gap-2">
                      {data.sessions.slice(0, 20).map((s, i) => (
                        <span key={i} className="rounded-lg border border-border bg-bg px-2.5 py-1 text-xs text-slate-300">
                          <span className={cn("font-mono", s.detect_rate !== null && s.detect_rate < 60 ? "text-severity-high" : "text-white")}>{s.detect_rate === null ? "n/a" : `${s.detect_rate}%`}</span>
                          <span className="text-slate-500"> detected · {fmtDate(s.played_at)}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </Card>
              </div>
            )}

            {/* ── Plan ────────────────────────────────────────────────── */}
            {tab === "plan" && <PersonalPrioritiesCard studentId={data.user_id} studentName={name} />}
          </>
        ) : null}
      </div>
    </div>
  );
}

function Metric({ icon, label, value, tone, hint, tip }: { icon: React.ReactNode; label: string; value: string; tone?: string; hint?: string; tip?: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg px-3 py-2.5" title={tip}>
      <p className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-slate-400">
        {icon}{label}{tip && <Info className="h-3 w-3 text-slate-500" aria-label={tip} />}
      </p>
      <p className={cn("mt-1 font-mono text-lg font-bold", tone ?? "text-white")}>{value}</p>
      {hint && <p className="text-[10px] text-slate-500">{hint}</p>}
    </div>
  );
}
