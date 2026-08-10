"use client";
/**
 * Per-student drill-down (org-admin / instructor). The roster row shows the
 * headline numbers; this is where an instructor opens a single student to see
 * their timeline: every scenario run with score + time, room-by-room progress,
 * and how long they take to answer (decision latency — captured all along in
 * room_progress.telemetry, surfaced here for the first time).
 *
 * Data + org-scoping come from GET /api/org/students/[id] (requireOrgAdmin;
 * the student is verified to be in the caller's org server-side).
 */
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import {
  ArrowLeft, Loader2, AlertTriangle, DoorOpen, Target, Trophy, Activity, Timer, Clock, KeyRound, CalendarDays, Gauge,
} from "lucide-react";
import type { StudentDetail } from "@/app/api/org/students/[id]/route";

function fmtMs(ms: number | null): string {
  if (ms === null) return "—";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  return `${m}m ${Math.round(s % 60)}s`;
}
function fmtSecs(sec: number | null): string {
  if (sec === null) return "—";
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}
function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export default function StudentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<StudentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetch(`/api/org/students/${id}`)
      .then(async r => (r.ok ? r.json() : Promise.reject((await r.json().catch(() => ({})))?.error ?? "Failed to load.")))
      .then(d => { if (!cancelled) { setData(d); setLoading(false); } })
      .catch(e => { if (!cancelled) { setError(String(e)); setLoading(false); } });
    return () => { cancelled = true; };
  }, [id]);

  const name = data?.display_name || data?.handle || (data ? data.user_id.slice(0, 8) : "Student");
  const affDays = data?.affiliation_expires_at ? Math.ceil((Date.parse(data.affiliation_expires_at) - Date.now()) / 86_400_000) : null;

  return (
    <div>
      <Topbar title="Student" subtitle="Progress & timeline" />
      <div className="container mx-auto max-w-[960px] px-6 py-6 space-y-6">
        <Link href="/manage" className="inline-flex items-center gap-1.5 text-sm text-slate-400 transition hover:text-white">
          <ArrowLeft className="h-4 w-4" /> Back to roster
        </Link>

        {error && <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>}

        {loading ? (
          <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
        ) : data ? (
          <>
            {/* Identity header */}
            <Card>
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <h1 className="text-xl font-bold text-white">{name}</h1>
                  <p className="mt-0.5 font-mono text-xs text-slate-400">
                    {data.handle ? `@${data.handle}` : ""} · {data.role} · {data.status}
                  </p>
                  <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-400">
                    <span><CalendarDays className="mr-1 inline h-3 w-3" />joined {fmtDate(data.joined_at)}</span>
                    <span><Clock className="mr-1 inline h-3 w-3" />last active {fmtDate(data.last_active_at)}</span>
                    {affDays !== null && (
                      <span className={affDays < 0 ? "font-bold text-severity-high" : affDays <= 14 ? "text-neon-amber" : ""}>
                        <KeyRound className="mr-1 inline h-3 w-3" />
                        {affDays < 0 ? "enrolment lapsed" : `enrolment ${affDays}d left`}
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

            {/* Summary metrics */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
              <Metric icon={<DoorOpen className="h-4 w-4" />} label="Rooms done" value={`${data.summary.rooms_completed}/${data.summary.rooms_started}`} />
              <Metric icon={<Target className="h-4 w-4" />} label="Scenarios" value={String(data.summary.scenarios_completed)} />
              <Metric icon={<Trophy className="h-4 w-4" />} label="Avg score" value={data.summary.scenario_avg_score === null ? "—" : `${data.summary.scenario_avg_score}%`} tone={data.summary.scenario_avg_score !== null && data.summary.scenario_avg_score < 60 ? "warn" : undefined} />
              <Metric icon={<Activity className="h-4 w-4" />} label="Sessions" value={String(data.summary.sessions)} />
              <Metric icon={<Gauge className="h-4 w-4" />} label="Avg detect" value={data.summary.avg_detect_rate === null ? "—" : `${data.summary.avg_detect_rate}%`} />
              <Metric icon={<Timer className="h-4 w-4" />} label="Median answer" value={fmtMs(data.summary.median_decision_latency_ms)} hint={`${data.summary.tasks_answered} tasks timed`} />
            </div>

            {/* Scenario timeline */}
            <Card>
              <h2 className="mb-3 flex items-center gap-2 text-sm font-bold text-white"><Target className="h-4 w-4 text-cyber-300" /> Scenario history</h2>
              {data.scenarios.length === 0 ? (
                <p className="text-sm text-slate-400">No scenarios completed yet.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead><tr className="border-b border-border text-[11px] uppercase tracking-wider text-slate-400">
                      <th className="py-2 pr-4 font-medium">Scenario</th>
                      <th className="py-2 pr-4 font-medium">Score</th>
                      <th className="py-2 pr-4 font-medium">Time</th>
                      <th className="py-2 font-medium">When</th>
                    </tr></thead>
                    <tbody className="divide-y divide-border/60">
                      {data.scenarios.map((s, i) => (
                        <tr key={`${s.slug}-${i}`}>
                          <td className="py-2 pr-4 text-slate-200">{s.title}</td>
                          <td className={`py-2 pr-4 font-mono ${s.score !== null && s.score < 60 ? "text-severity-high" : "text-slate-200"}`}>{s.score === null ? "—" : `${s.score}%`}</td>
                          <td className="py-2 pr-4 font-mono text-slate-400">{fmtSecs(s.time_taken)}</td>
                          <td className="py-2 text-[11px] text-slate-500">{fmtDate(s.completed_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>

            {/* Rooms with decision latency */}
            <Card>
              <h2 className="mb-1 flex items-center gap-2 text-sm font-bold text-white"><DoorOpen className="h-4 w-4 text-cyber-300" /> Rooms</h2>
              <p className="mb-3 text-[11px] text-slate-400">&quot;Avg answer&quot; is how long the student took to respond per task — from the decision-latency telemetry.</p>
              {data.rooms.length === 0 ? (
                <p className="text-sm text-slate-400">No rooms started yet.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead><tr className="border-b border-border text-[11px] uppercase tracking-wider text-slate-400">
                      <th className="py-2 pr-4 font-medium">Room</th>
                      <th className="py-2 pr-4 font-medium">Status</th>
                      <th className="py-2 pr-4 font-medium">Tasks</th>
                      <th className="py-2 pr-4 font-medium">XP</th>
                      <th className="py-2 pr-4 font-medium">Avg answer</th>
                      <th className="py-2 font-medium">Last touched</th>
                    </tr></thead>
                    <tbody className="divide-y divide-border/60">
                      {data.rooms.map(r => (
                        <tr key={r.room_id}>
                          <td className="py-2 pr-4 text-slate-200">{r.title}</td>
                          <td className="py-2 pr-4">
                            <span className={`rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase tracking-wider ${r.completed ? "border-neon-green/30 bg-neon-green/10 text-neon-green" : "border-slate-600 bg-slate-800/60 text-slate-400"}`}>
                              {r.completed ? "Done" : "In progress"}
                            </span>
                          </td>
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
          </>
        ) : null}
      </div>
    </div>
  );
}

function Metric({ icon, label, value, tone, hint }: { icon: React.ReactNode; label: string; value: string; tone?: "warn"; hint?: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg px-3 py-2.5">
      <p className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-slate-400">{icon}{label}</p>
      <p className={`mt-1 font-mono text-lg font-bold ${tone === "warn" ? "text-severity-high" : "text-white"}`}>{value}</p>
      {hint && <p className="text-[10px] text-slate-500">{hint}</p>}
    </div>
  );
}
