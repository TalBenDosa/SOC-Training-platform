"use client";
import { useEffect, useState } from "react";
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar,
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis,
  Tooltip, CartesianGrid,
} from "recharts";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { cn } from "@/lib/utils";
import { RANKS } from "@/lib/progression/ranks";
import { levelFromXp, xpForLevel, rankFromXp } from "@/lib/utils";
import { Award, CheckCircle2, Flame, Star, Target, TrendingUp, Zap, Timer, Eye, Scale, Snowflake } from "lucide-react";
import Link from "next/link";
import { ROOMS } from "@/data/rooms";
import type { RoomTask } from "@/data/rooms";
import { getTotalXp } from "@/lib/storage/progress";

// ─── Types ────────────────────────────────────────────────────────────────────

interface ScenarioRecord {
  slug: string;
  title: string;
  score: number;
  xpEarned: number;
  timeTaken: number;   // seconds
  date: string;
}

// ─── Static data (non-persisted) ─────────────────────────────────────────────

const BASE_USER = {
  displayName: "Tal Ben Dosa",
  handle: "tal.bendosa",
  streak: 0,
  badgesEarned: 1,
};

// Skills are computed dynamically from localStorage — this is the zero baseline.
// "Log Analysis" and "MITRE Knowledge" are derived from Learning Room task
// performance (real, per-task XP) rather than Dashboard per-event classification
// — the Dashboard has no per-event verdict UI anymore (removed by design; see
// PLATFORM_REVIEW.md), so there is no honest event-level accuracy signal left.
// "Threat Intel" (false-positive management) had no substitute once that UI was
// removed, so it's dropped rather than shown as a fake number.
const ZERO_SKILLS = [
  { skill: "Log Analysis",          value: 0 },
  { skill: "MITRE Knowledge",       value: 0 },
  { skill: "Threat Hunting",        value: 0 },
  { skill: "Incident Response",     value: 0 },
  { skill: "Detection Engineering", value: 0 },
];

// Shape mirrors DashboardSessionRecord in useLiveEvents.ts (kept local to avoid circular import)
interface DashboardSession {
  type: "dashboard";
  date: string;
  xpEarned: number;
  /** % of presented attacks actually caught (via a passing incident report) — real. */
  detectRate: number;
  fnCount?: number;
  avgCatchMs: number | null;
  attacksCaughtCount?: number;
  attacksPresentedCount?: number;
  eventsOpenedCount?: number;
  durationMs?: number;
}

// Shape mirrors TaskTelemetryEntry in lib/useTaskTelemetry.ts (kept local to avoid pulling
// client-only room-player code into this page)
interface RoomTaskTelemetry {
  taskId: string;
  decisionLatencyMs: number;
}

/** Consecutive-day streak ending today (or yesterday) from activity dates */
function computeStreak(dates: string[]): number {
  if (dates.length === 0) return 0;
  const daySet = new Set(dates.map(d => new Date(d).toDateString()));
  let streak = 0;
  const cursor = new Date();
  // Allow the streak to be "alive" if the last activity was yesterday
  if (!daySet.has(cursor.toDateString())) cursor.setDate(cursor.getDate() - 1);
  while (daySet.has(cursor.toDateString())) {
    streak += 1;
    cursor.setDate(cursor.getDate() - 1);
  }
  return streak;
}

// ─── Streak freeze ────────────────────────────────────────────────────────────
// Duolingo-style grace: a missed day doesn't have to silently kill a streak the
// learner has been building. Up to STREAK_FREEZES_PER_MONTH freezes can retro-
// actively cover yesterday, so a lapse becomes a same-day save, not a loss the
// learner only discovers next time they open this page.
const STREAK_FREEZE_KEY = "soc_streak_freeze_dates";
const STREAK_FREEZES_PER_MONTH = 2;

/** Freeze dates used within the last 30 days (older ones don't count against the cap). */
function loadStreakFreezeDates(): string[] {
  try {
    const raw = JSON.parse(localStorage.getItem(STREAK_FREEZE_KEY) ?? "[]") as string[];
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    return raw.filter(d => new Date(d).getTime() >= cutoff);
  } catch { return []; }
}

function saveStreakFreezeDates(dates: string[]) {
  try { localStorage.setItem(STREAK_FREEZE_KEY, JSON.stringify(dates)); } catch { /* ignore */ }
}

function avg(arr: number[]): number {
  return arr.length === 0 ? 0 : Math.round(arr.reduce((a, b) => a + b, 0) / arr.length);
}

/** Max XP a single Room task can award (0 for reading tasks) — mirrors taskMaxXp in RoomClient.tsx */
function roomTaskMaxXp(task: RoomTask): number {
  switch (task.type) {
    case "reading":      return 0;
    case "log_analysis": return task.questions.reduce((s, q) => s + q.xp, 0);
    default:              return task.xp;
  }
}

/** % score across every completed Room log_analysis task — the real substitute for
 * the old per-event "Log Analysis" accuracy, which required a Dashboard verdict
 * UI that no longer exists. */
function computeLogAnalysisSkill(perTaskXp: Record<string, number>): number {
  const rates: number[] = [];
  for (const room of ROOMS) {
    for (const task of room.tasks) {
      if (task.type !== "log_analysis") continue;
      const max = roomTaskMaxXp(task);
      const earned = perTaskXp[task.id];
      if (max <= 0 || earned === undefined) continue;
      rates.push(Math.round((earned / max) * 100));
    }
  }
  return rates.length > 0 ? avg(rates) : 0;
}

/** % score across every completed Room task whose embedded event carries a MITRE
 * technique (log_analysis + analyst_choice) — real substitute for the old
 * per-event technique hit-rate. */
function computeMitreKnowledgeSkill(perTaskXp: Record<string, number>): number {
  const rates: number[] = [];
  for (const room of ROOMS) {
    for (const task of room.tasks) {
      const event = task.type === "log_analysis" || task.type === "analyst_choice" ? task.event : undefined;
      if (!event?.mitre_technique) continue;
      const max = roomTaskMaxXp(task);
      const earned = perTaskXp[task.id];
      if (max <= 0 || earned === undefined) continue;
      rates.push(Math.round((earned / max) * 100));
    }
  }
  return rates.length > 0 ? avg(rates) : 0;
}

// Incident-Response catch-speed scoring bounds. Mirrors SLA_SECONDS (480s = 8min)
// in useLiveEvents.ts: a catch right at the SLA boundary scores 0, a fast one
// (90s) scores 100. Keep this in sync if SLA_SECONDS ever changes.
const CATCH_SPEED_BEST_MS  = 90_000;
const CATCH_SPEED_WORST_MS = 480_000;

function computeSkills(sessions: DashboardSession[], scenarioAvg: number, roomPerTaskXp: Record<string, number>): { skill: string; value: number }[] {
  const logAnalysis    = computeLogAnalysisSkill(roomPerTaskXp);
  const mitreKnowledge = computeMitreKnowledgeSkill(roomPerTaskXp);

  if (sessions.length === 0 && scenarioAvg === 0 && logAnalysis === 0 && mitreKnowledge === 0) return ZERO_SKILLS;

  // Threat Hunting — % of presented attacks actually caught (real: attacksCaughtCount/attacksPresentedCount)
  const threatHunting = sessions.length > 0 ? avg(sessions.map(s => s.detectRate)) : 0;

  // Incident Response — catch speed, calibrated to the real 8-minute SLA window
  const catchTimes = sessions.map(s => s.avgCatchMs).filter((v): v is number => v !== null);
  let incidentResponse = 0;
  if (catchTimes.length > 0) {
    const avgMs = avg(catchTimes);
    incidentResponse = Math.max(0, Math.min(100, Math.round(((CATCH_SPEED_WORST_MS - avgMs) / (CATCH_SPEED_WORST_MS - CATCH_SPEED_BEST_MS)) * 100)));
  }

  // Detection Engineering — from scenario history if available, else dashboard detect rate
  const detectionEngineering = scenarioAvg > 0 ? scenarioAvg : threatHunting;

  return [
    { skill: "Log Analysis",          value: logAnalysis },
    { skill: "MITRE Knowledge",       value: mitreKnowledge },
    { skill: "Threat Hunting",        value: threatHunting },
    { skill: "Incident Response",     value: incidentResponse },
    { skill: "Detection Engineering", value: detectionEngineering },
  ];
}

interface BadgeDef { name: string; tier: string; desc: string }

/** Achievements derived from real activity data — no separate persistence */
function computeBadges(
  sessions: DashboardSession[],
  scenarios: ScenarioRecord[],
  clearedCompanies: number,
  totalXp: number,
): BadgeDef[] {
  const badges: BadgeDef[] = [
    { name: "First Login", tier: "bronze", desc: "Logged in for the first time" },
  ];
  if (sessions.some(s => (s.attacksCaughtCount ?? 0) >= 1))
    badges.push({ name: "First Blood", tier: "bronze", desc: "Caught your first attack in the live feed" });
  if (scenarios.length >= 1)
    badges.push({ name: "Scenario Rookie", tier: "bronze", desc: "Completed your first full scenario" });
  if (clearedCompanies >= 1)
    badges.push({ name: "Company Secured", tier: "silver", desc: "Passed an incident report and secured a company" });
  if (clearedCompanies >= 3)
    badges.push({ name: "Portfolio Defender", tier: "gold", desc: "Secured 3 or more companies" });
  if (sessions.some(s => s.detectRate >= 80))
    badges.push({ name: "Sharp Eye", tier: "silver", desc: "Finished a session catching 80%+ of the attacks presented" });
  if (levelFromXp(totalXp) >= 5)
    badges.push({ name: "Level 5 Analyst", tier: "gold", desc: "Reached level 5" });
  return badges;
}

// Rank ladder comes from lib/progression/ranks.ts — the same list the Topbar
// and /home render. This file previously declared its own with different names
// AND different thresholds, so the two screens disagreed about what rank the
// learner held.
const RANK_LADDER = RANKS.map(r => ({ name: `${r.label} (${r.tier})`, xp: r.minXp }));

// ─── Sub-components ───────────────────────────────────────────────────────────

function XpLevel({ xp }: { xp: number }) {
  const level      = levelFromXp(xp);
  const thisLvlXp  = xpForLevel(level - 1);
  const nextLvlXp  = xpForLevel(level);
  const progress   = ((xp - thisLvlXp) / (nextLvlXp - thisLvlXp)) * 100;
  const rank       = rankFromXp(xp);

  return (
    <Card className="border-cyber-500/30 bg-gradient-to-br from-cyber-500/5 to-neon-purple/5">
      <div className="flex items-center gap-5">
        <div className="flex h-16 w-16 items-center justify-center rounded-full border-2 border-cyber-500/40 bg-cyber-500/10 font-mono text-2xl font-bold text-cyber-300">
          {level}
        </div>
        <div className="flex-1">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-cyber-300">Level {level} — {rank}</p>
          <div className="mt-2 flex items-center gap-3">
            <Star className="h-5 w-5 text-severity-medium" />
            <span className="font-mono text-3xl font-bold text-white">{xp.toLocaleString()} XP</span>
          </div>
          <div className="mt-2 flex items-center gap-2 text-xs text-slate-400">
            <span>{thisLvlXp.toLocaleString()} XP</span>
            <div className="relative h-2 flex-1 overflow-hidden rounded-full bg-bg">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyber-500 to-neon-green transition-all"
                style={{ width: `${progress}%` }}
              />
            </div>
            <span>{nextLvlXp.toLocaleString()} XP</span>
          </div>
          <p className="mt-0.5 text-[10px] text-slate-500">
            {nextLvlXp - xp} XP to Level {level + 1}
          </p>
        </div>
      </div>
    </Card>
  );
}

type UserData = typeof BASE_USER & { xp: number; scenariosCompleted: number; avgScore: number; timeSpentMinutes: number; clearedCompanies: number };
function StatsStrip({ user }: { user: UserData }) {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {[
        { label: "Scenarios Completed", value: user.scenariosCompleted, sub: `${user.scenariosCompleted} attempted`, icon: <CheckCircle2 className="h-4 w-4" />, accent: "cyber" },
        { label: "Average Score",       value: `${user.avgScore}%`,     sub: `${user.clearedCompanies}/5 companies secured`, icon: <TrendingUp className="h-4 w-4" />, accent: "green" },
        { label: "Current Streak",      value: user.streak,             sub: user.streak > 0 ? `${user.streak} day${user.streak > 1 ? "s" : ""} in a row` : "Train today to start one", icon: <Flame className="h-4 w-4" />, accent: "amber" },
        { label: "Time Spent",          value: user.timeSpentMinutes >= 60 ? `${Math.floor(user.timeSpentMinutes / 60)}h ${user.timeSpentMinutes % 60}m` : `${user.timeSpentMinutes}m`, sub: "Scenarios + dashboard sessions", icon: <Target className="h-4 w-4" />, accent: "purple" },
      ].map(({ label, value, sub, icon, accent }) => {
        const accentMap: Record<string, string> = {
          cyber:  "from-cyber-500/15 to-transparent text-cyber-300",
          green:  "from-neon-green/15 to-transparent text-neon-green",
          amber:  "from-severity-medium/20 to-transparent text-severity-medium",
          purple: "from-neon-purple/15 to-transparent text-neon-purple",
        };
        return (
          <div key={label} className="relative overflow-hidden rounded-lg border border-border bg-bg-elevated p-4">
            <div className={cn("pointer-events-none absolute inset-0 bg-gradient-to-br opacity-60", accentMap[accent])} />
            <div className="relative flex items-start justify-between">
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">{label}</p>
                <p className="mt-2 font-mono text-3xl font-semibold text-white">{value}</p>
                <p className="mt-0.5 text-xs text-slate-500">{sub}</p>
              </div>
              <div className={cn("rounded-lg border border-border p-2", accentMap[accent])}>{icon}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function ProgressPage() {
  const [totalXp,          setTotalXp]          = useState(0);
  const [streakFreezeDates, setStreakFreezeDates] = useState<string[]>([]);
  const [scenarioHistory,  setScenarioHistory]  = useState<ScenarioRecord[]>([]);
  const [dashSessions,     setDashSessions]     = useState<DashboardSession[]>([]);
  const [roomDates,        setRoomDates]        = useState<string[]>([]);
  const [roomTelemetry,    setRoomTelemetry]    = useState<RoomTaskTelemetry[]>([]);
  const [clearedCount,     setClearedCount]     = useState(0);
  const [skillsData,       setSkillsData]       = useState(ZERO_SKILLS);
  const [activityData,     setActivityData]     = useState([
    { day: "Mon", xp: 0 }, { day: "Tue", xp: 0 }, { day: "Wed", xp: 0 },
    { day: "Thu", xp: 0 }, { day: "Fri", xp: 0 }, { day: "Sat", xp: 0 }, { day: "Sun", xp: 0 },
  ]);

  useEffect(() => {
    // Read total XP (via the storage facade — Phase-1 seam)
    setTotalXp(getTotalXp());
    setStreakFreezeDates(loadStreakFreezeDates());

    // Room completions count toward the streak too — a learner who does rooms
    // daily should not show a streak of 0 just because they haven't run a
    // dashboard session.
    //
    // perTaskXp is ALSO the real data source for the "Log Analysis" and "MITRE
    // Knowledge" skill-radar entries below (see computeLogAnalysisSkill /
    // computeMitreKnowledgeSkill) — the Dashboard's per-event classify UI that
    // used to feed those was removed by design, so Room task performance is
    // the only honest signal left for per-source / per-technique accuracy.
    const roomPerTaskXp: Record<string, number> = {};
    try {
      const rp = JSON.parse(localStorage.getItem("room_progress") ?? "{}") as Record<string, { completedAt?: string; telemetry?: RoomTaskTelemetry[]; perTaskXp?: Record<string, number> }>;
      setRoomDates(Object.values(rp).map(r => r.completedAt).filter((d): d is string => !!d));
      setRoomTelemetry(Object.values(rp).flatMap(r => r.telemetry ?? []));
      for (const entry of Object.values(rp)) Object.assign(roomPerTaskXp, entry.perTaskXp ?? {});
    } catch { /* ignore corrupt data */ }

    let scenarioAvg = 0;
    // Read scenario history
    try {
      const raw = localStorage.getItem("soc_scenario_history");
      if (raw) {
        const history: ScenarioRecord[] = JSON.parse(raw);
        const sorted = history.slice().reverse().slice(0, 20);
        setScenarioHistory(sorted);
        scenarioAvg = history.length
          ? Math.round(history.reduce((s, r) => s + r.score, 0) / history.length)
          : 0;

        // Build last-7-days activity chart from scenario completions
        const days: Record<string, number> = {};
        const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        history.forEach(r => {
          const d = new Date(r.date);
          const dayLabel = dayNames[d.getDay()];
          days[dayLabel] = (days[dayLabel] ?? 0) + r.xpEarned;
        });
        setActivityData(prev => prev.map(d => ({ ...d, xp: days[d.day] ?? 0 })));
      }
    } catch { /* ignore corrupt data */ }

    // Read dashboard sessions and compute real skills
    try {
      const raw = localStorage.getItem("soc_dashboard_sessions");
      const sessions: DashboardSession[] = raw ? JSON.parse(raw) : [];
      setDashSessions(sessions);
      // Merge XP from dashboard sessions into activity chart
      const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
      const days: Record<string, number> = {};
      sessions.forEach(s => {
        const d = new Date(s.date);
        const dayLabel = dayNames[d.getDay()];
        days[dayLabel] = (days[dayLabel] ?? 0) + s.xpEarned;
      });
      setActivityData(prev => prev.map(d => ({ ...d, xp: (d.xp ?? 0) + (days[d.day] ?? 0) })));
      setSkillsData(computeSkills(sessions, scenarioAvg, roomPerTaskXp));
    } catch { /* ignore corrupt data */ }

    // Companies secured — drives completion rate + badges
    try {
      const cleared = JSON.parse(localStorage.getItem("soc_company_cleared_v1") ?? "[]") as string[];
      setClearedCount(cleared.length);
    } catch { /* ignore corrupt data */ }
  }, []);

  // Streak freezes are merged straight into the activity list — a frozen day
  // counts exactly like a real one, both for the streak number and for whether
  // the chain-bridging conditions below see it as "covered."
  const activityDates = [
    ...scenarioHistory.map(s => s.date),
    ...dashSessions.map(s => s.date),
    ...roomDates,
    ...streakFreezeDates,
  ];
  const streak = computeStreak(activityDates);

  const activityDaySet = new Set(activityDates.map(d => new Date(d).toDateString()));
  const todayStr     = new Date().toDateString();
  const yesterdayD   = new Date(); yesterdayD.setDate(yesterdayD.getDate() - 1);
  const twoDaysAgoD  = new Date(); twoDaysAgoD.setDate(twoDaysAgoD.getDate() - 2);
  const hasToday        = activityDaySet.has(todayStr);
  const hasYesterday    = activityDaySet.has(yesterdayD.toDateString());
  const hasTwoDaysAgo   = activityDaySet.has(twoDaysAgoD.toDateString());
  // Alive only via yesterday's grace period — tomorrow it breaks unless the
  // learner does something today. Worth a same-day nudge, not a silent lapse.
  const streakAtRisk    = streak > 0 && !hasToday;
  // The chain just snapped (yesterday was skipped entirely) but there was a
  // real streak running up to two days ago — a freeze bridges exactly that gap.
  const freezesAvailable = Math.max(0, STREAK_FREEZES_PER_MONTH - streakFreezeDates.length);
  const canUseFreeze = streak === 0 && !hasYesterday && !hasToday && hasTwoDaysAgo && freezesAvailable > 0;

  function handleUseStreakFreeze() {
    const updated = [...streakFreezeDates, yesterdayD.toISOString()];
    setStreakFreezeDates(updated);
    saveStreakFreezeDates(updated);
  }
  const dashboardMinutes = Math.round(
    dashSessions.reduce((sum, s) => sum + (s.durationMs ?? 0), 0) / 60_000
  );
  const user = {
    ...BASE_USER,
    xp: totalXp,
    streak,
    scenariosCompleted: scenarioHistory.length,
    avgScore: scenarioHistory.length
      ? Math.round(scenarioHistory.reduce((s, r) => s + r.score, 0) / scenarioHistory.length)
      : 0,
    timeSpentMinutes: Math.round(scenarioHistory.reduce((s, r) => s + r.timeTaken, 0) / 60) + dashboardMinutes,
    clearedCompanies: clearedCount,
  };

  const badges = computeBadges(dashSessions, scenarioHistory, clearedCount, totalXp);

  // Phase-1 behavioral telemetry (see ANALYST_TELEMETRY_PLAN.md) — a couple of
  // the most legible trends, not a dump of every raw metric. Speed is always
  // shown alongside accuracy, never in place of it.
  const avgDecisionLatencyMs = roomTelemetry.length
    ? Math.round(roomTelemetry.reduce((s, t) => s + t.decisionLatencyMs, 0) / roomTelemetry.length)
    : null;
  const totalFn = dashSessions.reduce((s, d) => s + (d.fnCount ?? 0), 0);
  // Real catch rate — caught/presented across all sessions, driven by markCaught()
  // firing on a passing incident report (no per-event classify UI exists anymore).
  const totalCaught    = dashSessions.reduce((s, d) => s + (d.attacksCaughtCount ?? 0), 0);
  const totalPresented = dashSessions.reduce((s, d) => s + (d.attacksPresentedCount ?? 0), 0);
  const catchRate = totalPresented > 0 ? Math.round((totalCaught / totalPresented) * 100) : null;
  const avgEventsOpened = dashSessions.length
    ? Math.round(dashSessions.reduce((s, d) => s + (d.eventsOpenedCount ?? 0), 0) / dashSessions.length)
    : null;
  const hasTelemetry = roomTelemetry.length > 0 || dashSessions.length > 0;

  return (
    <div>
      <Topbar
        title="Progress Dashboard"
        subtitle="Track your SOC training progress and achievements"
      />
      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-6">

        {/* XP / Level hero */}
        <XpLevel xp={totalXp} />

        {/* Stats strip */}
        <StatsStrip user={user} />

        {/* Streak-at-risk nudge — a same-day chance to act, not a silent loss
            discovered next visit. Freeze offer only appears the day a single
            missed day would otherwise have already zeroed the streak. */}
        {streakAtRisk && (
          <div className="flex items-center gap-3 rounded-lg border border-severity-medium/40 bg-severity-medium/5 px-5 py-3">
            <Flame className="h-4 w-4 shrink-0 text-severity-medium" />
            <p className="text-sm text-slate-200">
              Your <span className="font-semibold text-severity-medium">{streak}-day streak</span> is still alive — do a room, scenario, or dashboard session today to keep it going.
            </p>
          </div>
        )}
        {canUseFreeze && (
          <div className="flex items-center gap-3 rounded-lg border border-cyber-500/40 bg-cyber-500/5 px-5 py-3">
            <Snowflake className="h-4 w-4 shrink-0 text-cyber-300" />
            <p className="flex-1 text-sm text-slate-200">
              Looks like yesterday got away from you — a streak freeze covers it, no questions asked. {freezesAvailable} left this month.
            </p>
            <button
              onClick={handleUseStreakFreeze}
              className="shrink-0 rounded-md border border-cyber-500/50 bg-cyber-500/15 px-3 py-1.5 text-xs font-bold text-cyber-300 hover:bg-cyber-500/25 transition-colors"
            >
              Use a Freeze
            </button>
          </div>
        )}

        {/* Behavioral telemetry (Phase 1 — see ANALYST_TELEMETRY_PLAN.md).
            Speed and thoroughness are always shown next to accuracy signals
            (false positives/negatives), never as a stand-in for correctness —
            a fast wrong answer must never look better than a slow right one. */}
        {hasTelemetry && (
          <Card>
            <h3 className="flex items-center gap-2 text-sm font-semibold text-white">
              <Timer className="h-4 w-4 text-cyber-300" />
              Investigation Behavior
            </h3>
            <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="rounded-lg border border-border bg-bg-elevated p-3">
                <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                  <Timer className="h-3.5 w-3.5 text-cyber-300" /> Avg. Decision Time
                </div>
                <p className="mt-1.5 font-mono text-xl font-bold text-white">
                  {avgDecisionLatencyMs !== null
                    ? avgDecisionLatencyMs >= 60_000
                      ? `${Math.round(avgDecisionLatencyMs / 60_000)}m`
                      : `${Math.round(avgDecisionLatencyMs / 1000)}s`
                    : "—"}
                </p>
                <p className="mt-0.5 text-[10px] text-slate-500">Per room task — paired with accuracy, not a replacement for it</p>
              </div>
              <div className="rounded-lg border border-border bg-bg-elevated p-3">
                <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                  <Eye className="h-3.5 w-3.5 text-neon-purple" /> Events Opened / Session
                </div>
                <p className="mt-1.5 font-mono text-xl font-bold text-white">{avgEventsOpened ?? "—"}</p>
                <p className="mt-0.5 text-[10px] text-slate-500">Investigation thoroughness on the Dashboard</p>
              </div>
              <div className="rounded-lg border border-border bg-bg-elevated p-3">
                {/* Neutral framing, not a red "failure" tile — a miss is a
                    learning moment (see the in-session debrief), not a mark
                    against the student. */}
                <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-widest text-slate-400">
                  <Scale className="h-3.5 w-3.5 text-neon-amber" /> Catch Rate / Missed Attacks
                </div>
                <p className="mt-1.5 font-mono text-xl font-bold text-white">{catchRate ?? "—"}{catchRate !== null && "%"} <span className="text-slate-600">/</span> {totalFn}</p>
                <p className="mt-0.5 text-[10px] text-slate-500">Attacks caught before the SLA expired vs. ones that slipped past</p>
              </div>
            </div>
          </Card>
        )}

        {/* Charts row */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">

          {/* Activity chart */}
          <Card>
            <div className="flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-white">
                <TrendingUp className="h-4 w-4 text-cyber-300" />
                Activity Progress (Last 7 Days)
              </h3>
              <span className="text-xs text-slate-500">XP earned per day</span>
            </div>
            <div className="mt-4 h-48">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activityData}>
                  <defs>
                    <linearGradient id="xpGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#22c9f7" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#22c9f7" stopOpacity={0}   />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e2a38" />
                  <XAxis dataKey="day" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: "#0d1520", border: "1px solid #1e2a38", borderRadius: 6 }}
                    labelStyle={{ color: "#94a3b8" }}
                    itemStyle={{ color: "#22c9f7" }}
                    formatter={(v: number) => [`${v} XP`, "XP Earned"]}
                  />
                  <Area type="monotone" dataKey="xp" stroke="#22c9f7" fill="url(#xpGrad)" strokeWidth={2} dot={{ fill: "#22c9f7", r: 3 }} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>

          {/* Skills radar */}
          <Card>
            <div className="flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-sm font-semibold text-white">
                <Zap className="h-4 w-4 text-neon-purple" />
                Skills Breakdown
              </h3>
              <span className="text-xs text-slate-500">Based on your activity</span>
            </div>
            <div className="mt-2 h-56">
              <ResponsiveContainer width="100%" height="100%">
                <RadarChart data={skillsData} outerRadius="75%">
                  <PolarGrid stroke="#1e2a38" />
                  <PolarAngleAxis
                    dataKey="skill"
                    tick={{ fill: "#64748b", fontSize: 9 }}
                  />
                  <Radar
                    name="Skills"
                    dataKey="value"
                    stroke="#a855f7"
                    fill="#a855f7"
                    fillOpacity={0.25}
                    strokeWidth={2}
                    dot={{ fill: "#a855f7", r: 3 }}
                  />
                </RadarChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-1 grid grid-cols-2 gap-1.5">
              {skillsData.map(s => (
                <div key={s.skill} className="flex items-center justify-between rounded border border-border bg-bg px-2 py-1">
                  <span className="text-[10px] text-slate-400">{s.skill}</span>
                  <div className="flex items-center gap-1.5">
                    <div className="h-1 w-12 overflow-hidden rounded bg-bg-elevated">
                      <div className="h-full rounded bg-neon-purple" style={{ width: `${s.value}%` }} />
                    </div>
                    <span className="font-mono text-[10px] text-neon-purple">{s.value}%</span>
                  </div>
                </div>
              ))}
            </div>
            <p className="mt-2 text-[10px] text-slate-600">
              Computed from your SOC Dashboard sessions and completed scenarios.
            </p>
          </Card>
        </div>

        {/* Scenario history + Leaderboard row */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[3fr_2fr]">

          {/* Scenario history */}
          <Card padded={false}>
            <div className="flex items-center justify-between border-b border-border px-5 py-3">
              <h3 className="text-sm font-semibold text-white">Scenario History</h3>
              <Link href="/scenarios" className="text-xs font-semibold text-cyber-300 hover:text-cyber-200">
                Browse scenarios →
              </Link>
            </div>
            {scenarioHistory.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <Target className="h-8 w-8 text-slate-600" />
                <p className="mt-2 text-sm text-slate-400">No scenarios completed yet</p>
                <p className="mt-1 text-xs text-slate-600">Complete a scenario to see your results here</p>
                <Link href="/scenarios" className="mt-4">
                  <span className="rounded border border-cyber-500/40 bg-cyber-500/10 px-3 py-1.5 text-xs font-semibold text-cyber-300 hover:bg-cyber-500/20">
                    Start a Scenario
                  </span>
                </Link>
              </div>
            ) : (
              <table className="w-full text-xs">
                <thead className="text-left text-[10px] font-semibold uppercase tracking-widest text-slate-500">
                  <tr>
                    <th className="px-5 py-2">Scenario</th>
                    <th className="py-2">Date</th>
                    <th className="py-2">Score</th>
                    <th className="py-2">Time</th>
                    <th className="py-2 pr-5">XP</th>
                  </tr>
                </thead>
                <tbody>
                  {scenarioHistory.map((s, i) => {
                    const mins = Math.floor(s.timeTaken / 60);
                    const secs = s.timeTaken % 60;
                    return (
                      <tr key={i} className="border-t border-border/60 hover:bg-bg-hover">
                        <td className="px-5 py-2.5 text-slate-200">{s.title ?? s.slug}</td>
                        <td className="py-2.5 text-slate-400">{new Date(s.date).toLocaleDateString("en-GB")}</td>
                        <td className="py-2.5"><span className={cn("font-mono font-bold", s.score >= 80 ? "text-neon-green" : s.score >= 60 ? "text-severity-medium" : "text-severity-critical")}>{s.score}%</span></td>
                        <td className="py-2.5 font-mono text-slate-400">{mins}:{String(secs).padStart(2,"0")}</td>
                        <td className="py-2.5 pr-5 font-mono font-bold text-cyber-300">+{s.xpEarned}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </Card>

          {/* Right column */}
          <div className="space-y-4">

            {/* Rank progression ladder — honest milestones vs the learner's real XP */}
            <Card padded={false}>
              <div className="flex items-center justify-between border-b border-border px-5 py-3">
                <h3 className="text-sm font-semibold text-white">Rank Progression</h3>
                <span className="text-[10px] uppercase tracking-wider text-slate-500">Your XP: {totalXp.toLocaleString()}</span>
              </div>
              <ul>
                {RANK_LADDER.map((tier, i) => {
                  const nextXp   = RANK_LADDER[i + 1]?.xp;
                  const achieved = totalXp >= tier.xp;
                  const current  = achieved && (nextXp === undefined || totalXp < nextXp);
                  return (
                    <li
                      key={tier.name}
                      className={cn(
                        "flex items-center gap-3 border-b border-border/60 px-5 py-2.5",
                        current && "bg-cyber-500/5 border-l-2 border-l-cyber-500"
                      )}
                    >
                      <div className={cn(
                        "flex h-7 w-7 items-center justify-center rounded-full border font-mono text-[10px] font-bold",
                        current   ? "border-cyber-500/50 bg-cyber-500/15 text-cyber-300" :
                        achieved  ? "border-neon-green/40 bg-neon-green/10 text-neon-green" :
                                    "border-border bg-bg text-slate-600"
                      )}>
                        {achieved ? "✓" : i + 1}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className={cn(
                          "text-xs font-semibold truncate",
                          current ? "text-cyber-300" : achieved ? "text-slate-200" : "text-slate-500"
                        )}>
                          {tier.name}
                          {current && <span className="ml-1 text-[10px] text-cyber-500">(you)</span>}
                        </p>
                      </div>
                      <span className={cn("font-mono text-xs font-bold", achieved ? "text-cyber-300" : "text-slate-600")}>
                        {tier.xp.toLocaleString()} XP
                      </span>
                    </li>
                  );
                })}
              </ul>
            </Card>

            {/* Badges */}
            <Card>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-white">
                <Award className="h-4 w-4 text-severity-medium" /> Achievements
              </h3>
              <ul className="mt-3 space-y-2">
                {badges.map(b => (
                  <li key={b.name} className="flex items-center gap-3 rounded border border-border bg-bg px-3 py-2">
                    <Award className={cn(
                      "h-4 w-4 shrink-0",
                      b.tier === "gold"   ? "text-severity-medium" :
                      b.tier === "silver" ? "text-slate-300" :
                                            "text-cyber-400"
                    )} />
                    <div className="min-w-0">
                      <p className="text-xs font-semibold text-slate-100">{b.name}</p>
                      <p className="text-[10px] text-slate-500">{b.desc}</p>
                    </div>
                    <Badge variant="outline" className="shrink-0">{b.tier}</Badge>
                  </li>
                ))}
                {badges.length < 5 && (
                  <li className="rounded border border-dashed border-border px-3 py-2 text-center text-[10px] text-slate-600">
                    Catch attacks, secure companies and complete scenarios to unlock more badges
                  </li>
                )}
              </ul>
            </Card>

          </div>
        </div>

      </div>
    </div>
  );
}
