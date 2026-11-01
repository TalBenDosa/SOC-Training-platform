"use client";
import { useState } from "react";
import Link from "next/link";
import { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer, Legend } from "recharts";
import { FileText, Radio, Users, BookOpen, Cpu, TrendingUp, Printer } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/utils";
import type { IncidentRow, ProgressPayload, ScenarioAttemptView } from "@/lib/progress/selfView";
import { fmtDate, fmtDateTime, fmtMs, scoreTone } from "./format";
import { Bar, EmptyState, SectionTitle } from "./ui";

type Section = "scenarios" | "incidents" | "team" | "quizzes" | "edr";

export function ReportsTab({ data }: { data: ProgressPayload["reports"] }) {
  const counts: Record<Section, number> = {
    scenarios: data.scenarios.length, incidents: data.incidents.length, team: data.team.length,
    quizzes: data.quizzes.length + data.lessons.length, edr: data.edr.length,
  };
  const first = (Object.keys(counts) as Section[]).find(k => counts[k] > 0) ?? "scenarios";
  const [section, setSection] = useState<Section>(first);
  const total = Object.values(counts).reduce((s, x) => s + x, 0);
  if (total === 0) {
    return <EmptyState title="No reports yet" body="Every scenario report, live-feed incident report, team exercise review and quiz you finish will be kept here, with what the grader said and how to do better next time." action={<Link href="/scenarios" className="text-xs font-semibold text-cyber-300">Start a scenario →</Link>} />;
  }
  const tabs: { key: Section; label: string; icon: React.ReactNode }[] = [
    { key: "scenarios", label: "Scenarios", icon: <FileText aria-hidden="true" className="h-3.5 w-3.5" /> },
    { key: "incidents", label: "Live feed", icon: <Radio aria-hidden="true" className="h-3.5 w-3.5" /> },
    { key: "team", label: "Team", icon: <Users aria-hidden="true" className="h-3.5 w-3.5" /> },
    { key: "quizzes", label: "Quizzes", icon: <BookOpen aria-hidden="true" className="h-3.5 w-3.5" /> },
    { key: "edr", label: "EDR", icon: <Cpu aria-hidden="true" className="h-3.5 w-3.5" /> },
  ];
  return (
    <div className="space-y-4">
      <Quality q={data.quality} />
      <div className="flex flex-wrap items-center gap-2">
        <div role="group" aria-label="Report type" className="flex flex-wrap gap-1.5">
          {tabs.map(t => (
            <button key={t.key} type="button" aria-pressed={section === t.key} onClick={() => setSection(t.key)}
              className={cn("inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-semibold",
                section === t.key ? "border-cyber-500/60 bg-cyber-500/15 text-cyber-300" : "border-border bg-bg text-slate-300 hover:bg-bg-hover")}>
              {t.icon}{t.label}<span className="font-mono text-[10px] text-slate-400">{counts[t.key]}</span>
            </button>
          ))}
        </div>
        <Link href="/progress/report" className="ml-auto inline-flex items-center gap-1.5 text-xs font-semibold text-cyber-300 hover:text-cyber-200">
          <Printer aria-hidden="true" className="h-3.5 w-3.5" /> Progress report to print
        </Link>
      </div>
      {section === "scenarios" && <Scenarios list={data.scenarios} />}
      {section === "incidents" && <Incidents list={data.incidents} />}
      {section === "team" && <Team list={data.team} />}
      {section === "quizzes" && <Quizzes quizzes={data.quizzes} lessons={data.lessons} />}
      {section === "edr" && <Edr list={data.edr} />}
    </div>
  );
}

function Quality({ q }: { q: ProgressPayload["reports"]["quality"] }) {
  if (q.points.length < 2) return null;
  const chart = q.points.map(p => ({ at: fmtDate(p.at), Identification: p.identification, Evidence: p.evidence, "Depth and reasoning": p.depth }));
  return (
    <Card>
      <SectionTitle icon={<TrendingUp aria-hidden="true" className="h-4 w-4 text-neon-green" />}
        info="Every scenario and live-feed report on one scale: the percent of each part's maximum. Identification = naming the attack; evidence = real indicators cited; depth = reasoning, action and impact.">
        Report quality over time
      </SectionTitle>
      {q.weakest && (
        <p className="mt-2 rounded-md border border-severity-medium/30 bg-severity-medium/5 px-3 py-2 text-[12px] text-slate-200">
          <strong className="capitalize">{q.weakest.key === "depth" ? "Depth and reasoning" : q.weakest.key}</strong> was your weakest part in {q.weakest.count} of your last {q.weakest.of} reports. {q.weakest.advice}
        </p>
      )}
      <div className="mt-3 h-52" role="img" aria-label={`Report quality: ${q.points.slice(-8).map(p => `${fmtDate(p.at)} identification ${p.identification}%, evidence ${p.evidence}%, depth ${p.depth}%`).join("; ")}.`}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chart} margin={{ left: -20, right: 8, top: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e2a38" />
            <XAxis dataKey="at" tick={{ fill: "#8190a5", fontSize: 10 }} axisLine={false} tickLine={false} />
            <YAxis domain={[0, 100]} tick={{ fill: "#8190a5", fontSize: 10 }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ background: "#0d1520", border: "1px solid #1e2a38", borderRadius: 6, fontSize: 12 }} labelStyle={{ color: "#94a3b8" }} />
            <Legend wrapperStyle={{ fontSize: 11, color: "#94a3b8" }} />
            <Line type="linear" dataKey="Identification" stroke="#22c9f7" strokeWidth={2} dot={{ r: 2 }} />
            <Line type="linear" dataKey="Evidence" stroke="#f59e0b" strokeWidth={2} dot={{ r: 2 }} />
            <Line type="linear" dataKey="Depth and reasoning" stroke="#a855f7" strokeWidth={2} dot={{ r: 2 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}

function Scenarios({ list }: { list: ProgressPayload["reports"]["scenarios"] }) {
  const [open, setOpen] = useState<string | null>(list[0] ? `${list[0].slug}|0` : null);
  if (!list.length) return <p className="text-sm text-slate-400">No scenario reports yet.</p>;
  return (
    <div className="space-y-3">
      {list.map(s => (
        <Card key={s.slug} padded={false}>
          <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-border px-4 py-3">
            <h3 className="text-sm font-semibold text-white" dir="auto">{s.title}</h3>
            <span className="text-[11px] text-slate-400">best <span className={cn("font-mono font-bold", scoreTone(s.best))}>{s.best}%</span> · {s.count} attempt{s.count === 1 ? "" : "s"}</span>
          </div>
          <ul>
            {s.attempts.map((a, i) => {
              const key = `${s.slug}|${i}`; const isOpen = open === key;
              const prev = s.attempts.slice(i + 1).find(x => !x.blind && x.items.length);
              return (
                <li key={key} className="border-t border-border/50 first:border-t-0">
                  <button type="button" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : key)}
                    className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-left hover:bg-bg-hover">
                    <span className="w-24 text-[12px] text-slate-400">{fmtDate(a.at)}</span>
                    <span className={cn("w-12 font-mono text-sm font-bold tabular-nums", scoreTone(a.score))}>{a.score}%</span>
                    {a.passed !== null && <span className={cn("rounded border px-1.5 text-[10px] font-semibold", a.passed ? "border-neon-green/40 text-neon-green" : "border-border text-slate-400")}>{a.passed ? "PASSED" : "NOT PASSED"}</span>}
                    {a.blind && <span className="text-[11px] text-slate-400">submitted in {a.timeS}s, not counted</span>}
                    <span className="ml-auto text-[11px] text-cyber-300">{isOpen ? "Hide" : "Show report"}</span>
                  </button>
                  {isOpen && <ScenarioReport a={a} prev={prev} />}
                </li>
              );
            })}
          </ul>
        </Card>
      ))}
    </div>
  );
}

function ScenarioReport({ a, prev }: { a: ScenarioAttemptView; prev?: ScenarioAttemptView }) {
  const prevByKey = new Map((prev?.items ?? []).map(x => [x.key, x.points]));
  return (
    <div className="space-y-3 border-t border-border/40 bg-bg/50 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2 text-[12px]">
        {a.verdict && <span className={cn("rounded border px-2 py-0.5 font-bold uppercase", a.verdict === "tp" ? "border-severity-critical/40 text-severity-critical" : "border-neon-green/40 text-neon-green")}>Verdict: {a.verdict === "tp" ? "Malicious" : a.verdict === "fp" ? "Benign" : a.verdict}</span>}
        {a.reportScore !== null && <span className="text-slate-300">Report {a.reportScore}/100</span>}
        {a.quizScore !== null && <span className="text-slate-300">Questions {a.quizScore}%{a.questions ? ` (${a.questions.filter(q => q.correct).length}/${a.questions.length})` : ""}</span>}
        <span className="text-slate-400">{Math.floor(a.timeS / 60)}:{String(a.timeS % 60).padStart(2, "0")}</span>
      </div>
      {a.items.length > 0 && (
        <ul className="space-y-1.5">
          {a.items.map(it => {
            const was = prevByKey.get(it.key); const d = was === undefined ? null : it.points - was;
            return (
              <li key={it.key}>
                <div className="flex items-baseline justify-between gap-2 text-[12px]">
                  <span className="text-slate-200">{it.label}</span>
                  <span className="font-mono tabular-nums text-slate-300">{it.points}/{it.max}{d !== null && d !== 0 && <span className={cn("ml-1.5 text-[11px]", d > 0 ? "text-neon-green" : "text-severity-high")}>{d > 0 ? "+" : ""}{d}</span>}</span>
                </div>
                <div className="mt-1"><Bar value={(it.points / it.max) * 100} cls={it.points / it.max >= 0.8 ? "bg-neon-green" : it.points / it.max >= 0.5 ? "bg-severity-medium" : "bg-severity-critical"} label={`${it.label}: ${it.points} of ${it.max}`} /></div>
                {it.detail && <p className="mt-0.5 text-[11px] text-slate-400">{it.detail}</p>}
              </li>
            );
          })}
        </ul>
      )}
      {prev && <p className="text-[11px] text-slate-400">Compared with your attempt on {fmtDate(prev.at)}.</p>}
      {a.improvements.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">What to improve</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 text-[12px] text-slate-200 [overflow-wrap:anywhere]">{a.improvements.map(x => <li key={x}>{x}</li>)}</ul>
        </div>
      )}
      {(a.citedIndicators.length > 0 || (a.missedIndicators?.length ?? 0) > 0 || a.fabricatedValues.length > 0 || a.misattributedValues.length > 0) && (
        <div className="grid gap-2 text-[12px] sm:grid-cols-2">
          {a.citedIndicators.length > 0 && <Chips label="Indicators you cited" values={a.citedIndicators} cls="border-neon-green/30 text-neon-green" />}
          {(a.missedIndicators?.length ?? 0) > 0 && <Chips label="Key indicators you missed" values={a.missedIndicators!} cls="border-severity-medium/30 text-severity-medium" />}
          {a.fabricatedValues.length > 0 && <Chips label="Not found in the logs" values={a.fabricatedValues} cls="border-severity-critical/30 text-severity-critical" />}
          {a.misattributedValues.length > 0 && <Chips label="Benign values tagged as hostile" values={a.misattributedValues} cls="border-severity-high/30 text-severity-high" />}
        </div>
      )}
      {a.aiFeedback && <p className="rounded-md border border-border bg-bg px-3 py-2 text-[12px] leading-relaxed text-slate-300 [overflow-wrap:anywhere]"><span className="text-slate-400">Grader: </span>{a.aiFeedback}</p>}
      {!a.hasDetail && <p className="text-[11px] text-slate-400">This attempt was recorded before the full breakdown was kept, so only the scores are shown.</p>}
      <div className="grid gap-2 sm:grid-cols-2">
        <TextBlock label="Your verdict reasoning" text={a.verdictReason} />
        <TextBlock label="Your analyst notes" text={a.notes} />
      </div>
    </div>
  );
}

function Chips({ label, values, cls }: { label: string; values: string[]; cls: string }) {
  return (
    <div>
      <p className="text-[11px] text-slate-400">{label}</p>
      <div className="mt-1 flex flex-wrap gap-1">{values.map(v => <code key={v} className={cn("break-all rounded border bg-bg px-1.5 py-0.5 text-[11px]", cls)}>{v}</code>)}</div>
    </div>
  );
}

function TextBlock({ label, text }: { label: string; text: string | null }) {
  return (
    <div className="rounded-md border border-border bg-bg px-3 py-2">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">{label}</p>
      <p className="mt-1 whitespace-pre-wrap text-[12px] leading-relaxed text-slate-300" dir="auto">{text?.trim() || <span className="italic text-slate-500">Left blank</span>}</p>
    </div>
  );
}

function Incidents({ list }: { list: IncidentRow[] }) {
  const [open, setOpen] = useState<number | null>(null);
  if (!list.length) return <EmptyState title="No live-feed reports yet" body="Incident reports you file during a live shift, and attacks that end without one, are kept here from now on." action={<Link href="/dashboard" className="text-xs font-semibold text-cyber-300">Start a shift →</Link>} />;
  const span = (a: string | null, b: string | null) => { if (!a || !b) return null; const d = Date.parse(b) - Date.parse(a); return d >= 0 ? d : null; };
  return (
    <Card padded={false}>
      <ul>
        {list.map(i => {
          const isOpen = open === i.id;
          return (
            <li key={i.id} className="border-t border-border/50 first:border-t-0">
              <button type="button" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : i.id)} className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-left hover:bg-bg-hover">
                <span className="w-28 text-[12px] text-slate-400">{fmtDateTime(i.submitted_at)}</span>
                <span className="min-w-0 flex-1 text-sm text-slate-100" dir="auto">{i.title}</span>
                {i.outcome === "missed" ? <span className="rounded border border-severity-high/40 px-1.5 text-[10px] font-semibold text-severity-high">MISSED</span>
                  : <span className={cn("font-mono text-sm font-bold tabular-nums", scoreTone(i.report_score ?? 0))}>{i.report_score ?? 0}<span className="text-[10px] text-slate-400">/100</span></span>}
              </button>
              {isOpen && (
                <div className="space-y-2 border-t border-border/40 bg-bg/50 px-4 py-3 text-[12px]">
                  <p className="text-slate-400">{[i.company, i.severity, (i.mitre ?? []).join(", ")].filter(Boolean).join(" · ")}</p>
                  {i.outcome === "missed" ? (
                    i.missed_tell && <p className="text-slate-200"><span className="text-slate-400">How to catch it next time: </span>{i.missed_tell}</p>
                  ) : (
                    <>
                      <ul className="grid gap-1.5 sm:grid-cols-3">
                        {[["Attack identification", i.attack_score, 40], ["Evidence", i.ioc_score, 30], ["Action and impact", i.action_score, 30]].map(([l, v, m]) => (
                          <li key={l as string}>
                            <div className="flex justify-between"><span className="text-slate-300">{l}</span><span className="font-mono tabular-nums text-slate-300">{v ?? "–"}/{m}</span></div>
                            <div className="mt-1"><Bar value={v == null ? 0 : ((v as number) / (m as number)) * 100} cls="bg-cyber-400" label={`${l}: ${v ?? 0} of ${m}`} /></div>
                          </li>
                        ))}
                      </ul>
                      <p className="text-slate-400">To notice {fmtMs(span(i.injected_at, i.first_opened_at))} · investigating {fmtMs(span(i.first_opened_at, i.report_opened_at))} · writing {fmtMs(span(i.report_opened_at, i.submitted_at))} · total {fmtMs(span(i.injected_at, i.submitted_at))} (target 15m)</p>
                      {i.feedback && <p className="whitespace-pre-wrap text-slate-200">{i.feedback}</p>}
                      {(i.strengths?.length ?? 0) > 0 && <ul className="list-disc pl-5 text-neon-green/90">{i.strengths!.map(s => <li key={s}>{s}</li>)}</ul>}
                      {(i.gaps?.length ?? 0) > 0 && <ul className="list-disc pl-5 text-severity-medium">{i.gaps!.map(s => <li key={s}>{s}</li>)}</ul>}
                      {i.summary && <TextBlock label="Your report" text={i.summary} />}
                    </>
                  )}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

function Team({ list }: { list: ProgressPayload["reports"]["team"] }) {
  if (!list.length) return <EmptyState title="No team exercises yet" body="When your class runs a team shift, your own card from the after-action review appears here." />;
  return (
    <div className="space-y-3">
      {list.map(t => (
        <Card key={t.sessionId}>
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h3 className="text-sm font-semibold text-white">Team exercise · {t.role ?? "member"}</h3>
            <span className="text-[11px] text-slate-400">{fmtDate(t.at)}{t.company ? ` · ${t.company}` : ""}</span>
          </div>
          {!t.ready ? (
            <p className="mt-2 text-[12px] text-slate-400">The review hasn&apos;t been opened yet. <Link href={`/team/${t.sessionId}`} className="font-semibold text-cyber-300">Open the after-action review →</Link></p>
          ) : (
            <>
              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-slate-300">
                <span>Rubric <strong className="font-mono">{t.rubricPct ?? "–"}%</strong></span>
                <span>SLA <strong className="font-mono">{t.slaTotal ? `${t.slaMet}/${t.slaTotal}` : "–"}</strong></span>
                {t.dispAcc !== null && <span>Verdict accuracy <strong className="font-mono">{t.dispAcc}%</strong></span>}
                {t.firstActionS !== null && <span>First action <strong className="font-mono">{fmtMs(t.firstActionS * 1000)}</strong></span>}
                {t.isolations > 0 && <span>Isolations <strong className="font-mono">{t.isoPct ?? "–"}% right</strong></span>}
                {t.forensicAccPct !== null && <span>Forensic findings <strong className="font-mono">{t.forensicAccPct}%</strong></span>}
                {t.blindCalls > 0 && <span className="text-severity-medium">{t.blindCalls} call{t.blindCalls === 1 ? "" : "s"} within 3s of opening</span>}
              </div>
              {t.insufficientEvidence && <p className="mt-1 text-[11px] text-slate-400">Not enough activity to rate every part of the rubric.</p>}
              {t.rubric.length > 0 && (
                <ul className="mt-2 grid gap-1.5 sm:grid-cols-2">
                  {t.rubric.map(c => (
                    <li key={c.label}>
                      <div className="flex justify-between text-[12px]"><span className="text-slate-300">{c.label}</span><span className="font-mono tabular-nums text-slate-300">{c.score}/12</span></div>
                      <div className="mt-1"><Bar value={(c.score / 12) * 100} cls="bg-pink-400" label={`${c.label}: ${c.score} of 12`} /></div>
                    </li>
                  ))}
                </ul>
              )}
              {t.misses.length > 0 && (
                <ul className="mt-3 space-y-1 text-[12px]">
                  {t.misses.map((m, i) => (
                    <li key={m.label + i} className="flex flex-wrap items-baseline gap-x-2">
                      <span className={cn("rounded border px-1 text-[10px] font-semibold uppercase", m.kind === "false alarm" ? "border-border text-slate-400" : "border-severity-high/40 text-severity-high")}>{m.kind}</span>
                      <span className="text-slate-200" dir="auto">{m.label}</span>
                      {m.practice && <Link href={`/rooms/${encodeURIComponent(m.practice.id)}`} className="text-[11px] font-semibold text-cyber-300">Practice →</Link>}
                    </li>
                  ))}
                </ul>
              )}
              <Link href={`/team/${t.sessionId}`} className="mt-3 inline-block text-[11px] font-semibold text-cyber-300">Full after-action review →</Link>
            </>
          )}
        </Card>
      ))}
    </div>
  );
}

function Quizzes({ quizzes, lessons }: { quizzes: ProgressPayload["reports"]["quizzes"]; lessons: ProgressPayload["reports"]["lessons"] }) {
  const rows = [
    ...quizzes.map(q => ({ key: `q|${q.slug}`, kind: "Quiz", title: q.title, best: q.best, passed: q.passed, attempts: q.attempts, href: `/quizzes/${encodeURIComponent(q.slug)}` })),
    ...lessons.map(l => ({ key: `l|${l.key}`, kind: "Lesson check", title: l.title, best: l.best, passed: l.passed, attempts: l.attempts, href: null as string | null })),
  ];
  if (!rows.length) return <p className="text-sm text-slate-400">No quizzes or lesson checks yet.</p>;
  return (
    <Card padded={false}>
      <ul>
        {rows.map(r => (
          <li key={r.key} className="border-t border-border/50 px-4 py-2.5 first:border-t-0">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span className="w-24 text-[10px] font-semibold uppercase tracking-wider text-slate-400">{r.kind}</span>
              <span className="min-w-0 flex-1 text-sm text-slate-100" dir="auto">{r.title}</span>
              <span className="text-[12px] text-slate-400">best <span className={cn("font-mono font-bold", scoreTone(r.best ?? 0))}>{r.best ?? "–"}%</span>{r.passed ? " · passed" : ""}</span>
              {r.href && <Link href={r.href} className="text-[11px] font-semibold text-cyber-300">Open</Link>}
            </div>
            {r.attempts.length > 0 && (
              <p className="mt-1 text-[11px] text-slate-400">Attempts: {r.attempts.slice(0, 10).map(a => `${a.score}% (${fmtDate(a.at)})`).join(" · ")}</p>
            )}
          </li>
        ))}
      </ul>
    </Card>
  );
}

function Edr({ list }: { list: ProgressPayload["reports"]["edr"] }) {
  if (!list.length) return <EmptyState title="No EDR cases yet" body="Verdicts from the practice cases in the EDR console are kept here." action={<Link href="/edr" className="text-xs font-semibold text-cyber-300">Open the EDR console →</Link>} />;
  return (
    <Card padded={false}>
      <ul>
        {list.map(e => (
          <li key={e.case_id + e.created_at} className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-border/50 px-4 py-2.5 first:border-t-0">
            <span className="w-28 text-[12px] text-slate-400">{fmtDateTime(e.created_at)}</span>
            <span className="min-w-0 flex-1 text-sm text-slate-100" dir="auto">{e.title ?? e.case_id}</span>
            <span className="text-[12px] text-slate-400">{e.chosen}</span>
            <span className={cn("rounded border px-1.5 text-[10px] font-semibold", e.correct ? "border-neon-green/40 text-neon-green" : "border-severity-high/40 text-severity-high")}>{e.correct ? "CORRECT" : "NOT QUITE"}</span>
            {e.duration_ms ? <span className="font-mono text-[11px] text-slate-400">{fmtMs(e.duration_ms)}</span> : null}
          </li>
        ))}
      </ul>
    </Card>
  );
}
