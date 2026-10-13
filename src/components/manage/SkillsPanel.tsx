"use client";
/**
 * The class's skills (org-admin /manage): "skills" mode shows the students × skill-area
 * heatmap and the class's mastery per area; "mistakes" mode shows the questions the class
 * misses most, with the wrong answer most of them chose. Data: GET /api/org/skills, loaded
 * once per page and shared by both tabs.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { Card } from "@/components/ui/Card";
import { Loader2, AlertTriangle, ExternalLink, Flag, Users } from "lucide-react";
import type { SkillsResponse } from "@/app/api/org/skills/route";
import { cn } from "@/lib/utils";

let cache: Promise<SkillsResponse> | null = null;
function loadSkills(): Promise<SkillsResponse> {
  cache ??= fetch("/api/org/skills").then(async r => {
    if (!r.ok) { cache = null; throw new Error((await r.json().catch(() => ({})))?.error ?? "Could not load skills."); }
    return r.json();
  });
  return cache;
}

function tone(acc: number | null, items: number, min: number): { cell: string; text: string; label: string } {
  if (items === 0 || acc === null) return { cell: "bg-transparent text-slate-700", text: "text-slate-600", label: "No answers yet" };
  if (items < min) return { cell: "bg-slate-800/60 text-slate-400", text: "text-slate-400", label: `Only ${items} answered: not enough to judge` };
  if (acc >= 80) return { cell: "bg-neon-green/20 text-neon-green", text: "text-neon-green", label: "Strong" };
  if (acc >= 60) return { cell: "bg-neon-amber/20 text-neon-amber", text: "text-neon-amber", label: "Developing" };
  return { cell: "bg-severity-high/25 text-severity-high", text: "text-severity-high", label: "Weak" };
}

const barOf = (acc: number | null, items: number, min: number) =>
  items < min || acc === null ? "bg-slate-600" : acc >= 80 ? "bg-neon-green" : acc >= 60 ? "bg-neon-amber" : "bg-severity-high";

export function SkillsPanel({ mode }: { mode: "skills" | "mistakes" }) {
  const [data, setData] = useState<SkillsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { loadSkills().then(setData, e => setError(e instanceof Error ? e.message : "Could not load skills.")); }, []);

  if (error) return <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>;
  if (!data) return <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>;
  const min = data.min_items;

  if (mode === "skills") {
    const weakestFirst = [...data.class_areas].filter(a => a.items > 0).sort((a, b) => (a.accuracy ?? 0) - (b.accuracy ?? 0));
    return (
      <div className="space-y-5">
        <Card>
          <h2 className="text-sm font-bold text-white">Students by skill area</h2>
          <p className="mb-3 mt-0.5 text-[11px] text-slate-400">Right first try in each area, from rooms, quizzes, lesson checks and scenario questions. Click a student to see their mistakes.</p>
          {data.students.length === 0 ? <p className="text-sm text-slate-400">No students yet.</p> : (
            <div className="overflow-x-auto">
              <table className="w-full border-separate border-spacing-[3px] text-xs">
                <thead>
                  <tr>
                    <th className="sticky left-0 bg-bg-elevated px-2 py-1 text-left font-medium text-slate-400">Student</th>
                    {data.areas.map(a => <th key={a.id} className="min-w-[64px] px-1 py-1 text-center text-[10px] font-medium leading-tight text-slate-400">{a.label}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {data.students.map(s => (
                    <tr key={s.user_id}>
                      <td className="sticky left-0 bg-bg-elevated px-2 py-1">
                        <Link href={`/manage/students/${s.user_id}?tab=mistakes`} className="whitespace-nowrap font-medium text-slate-200 hover:text-cyber-300"><bdi>{s.name}</bdi></Link>
                      </td>
                      {data.areas.map(a => {
                        const c = s.areas[a.id] ?? { items: 0, accuracy: null };
                        const t = tone(c.accuracy, c.items, min);
                        return (
                          <td key={a.id} className={cn("rounded px-1 py-1.5 text-center font-mono", t.cell)} title={`${a.label}: ${t.label}${c.items ? ` (${c.accuracy}% of ${c.items})` : ""}`}>
                            {c.items === 0 ? "" : c.items < min ? `n${c.items}` : c.accuracy}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="mt-3 flex flex-wrap gap-3 text-[10px] text-slate-400">
            <span><span className="mr-1 inline-block h-2.5 w-2.5 rounded bg-neon-green/40" />80%+ strong</span>
            <span><span className="mr-1 inline-block h-2.5 w-2.5 rounded bg-neon-amber/40" />60-79% developing</span>
            <span><span className="mr-1 inline-block h-2.5 w-2.5 rounded bg-severity-high/50" />under 60% weak</span>
            <span><span className="mr-1 inline-block h-2.5 w-2.5 rounded bg-slate-700" />n = fewer than {min} answers</span>
            <span>blank = no answers in that area yet</span>
          </div>
        </Card>

        <Card>
          <h2 className="mb-3 text-sm font-bold text-white">The class, weakest area first</h2>
          {weakestFirst.length === 0 ? <p className="text-sm text-slate-400">No answers yet.</p> : (
            <div className="space-y-2">
              {weakestFirst.map(a => {
                const t = tone(a.accuracy, a.items, min);
                return (
                  <div key={a.area} className="grid grid-cols-[150px_minmax(0,1fr)_auto] items-center gap-3 text-xs">
                    <span className="truncate text-slate-300">{a.label}</span>
                    <div className="h-2 rounded bg-bg"><div className={cn("h-2 rounded", barOf(a.accuracy, a.items, min))} style={{ width: `${a.accuracy ?? 0}%` }} /></div>
                    <span className={cn("whitespace-nowrap text-right font-mono", t.text)}>{a.accuracy}% <span className="text-slate-500">· {a.items} answers · {a.students_judged} judged</span></span>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    );
  }

  // ── Common mistakes ──
  return (
    <div className="space-y-3">
      <p className="text-sm text-slate-400">
        The room questions your class gets wrong most on the first try (asked of at least {Math.min(3, Math.max(1, data.students.length))} students).
        When many students choose the same wrong answer, the question or the lesson behind it may need a look.
      </p>
      {data.common_mistakes.length === 0 ? (
        <Card><p className="text-sm text-slate-400">No shared mistakes yet. They appear here once several students answer the same questions.</p></Card>
      ) : data.common_mistakes.map(m => (
        <Card key={m.key} className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn("rounded-full px-2 py-0.5 font-mono text-[11px] font-bold", m.rate >= 60 ? "bg-severity-high/15 text-severity-high" : "bg-neon-amber/15 text-neon-amber")}>{m.rate}% wrong first try</span>
            <span className="inline-flex items-center gap-1 text-[11px] text-slate-400"><Users className="h-3 w-3" aria-hidden="true" />{m.wrong_first} of {m.attempted} students</span>
            {m.reports > 0 && <span className="inline-flex items-center gap-1 rounded-full border border-neon-amber/40 px-2 py-0.5 text-[10px] text-neon-amber"><Flag className="h-3 w-3" aria-hidden="true" />{m.reports} report{m.reports === 1 ? "" : "s"}</span>}
            <a href={`/rooms/${m.room_id}`} target="_blank" rel="noopener noreferrer" className="ml-auto inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-white">
              Open room <ExternalLink className="h-3 w-3" aria-hidden="true" />
            </a>
          </div>
          <p className="text-[11px] text-slate-500">{m.room_title} · {m.task_position ?? "Task"} · {m.type_label}</p>
          {m.prompt && <p className="text-sm text-slate-200" dir="auto">{m.prompt}</p>}
          <div className="flex flex-wrap gap-1.5 text-[11px]">
            {m.common_wrong?.text && (
              <span className="rounded border border-severity-high/40 bg-severity-high/10 px-2 py-0.5 text-severity-high" dir="auto">
                Most chose: {m.common_wrong.text} <span className="text-slate-400">({m.common_wrong.count})</span>
              </span>
            )}
            {m.correct && <span className="rounded border border-neon-green/40 bg-neon-green/10 px-2 py-0.5 text-neon-green" dir="auto">Correct: {m.correct}</span>}
          </div>
          {m.explanation && (
            <details className="text-xs text-slate-400">
              <summary className="cursor-pointer select-none text-slate-500 hover:text-slate-300">Why</summary>
              <p className="mt-1 leading-relaxed" dir="auto">{m.explanation}</p>
            </details>
          )}
        </Card>
      ))}
    </div>
  );
}
