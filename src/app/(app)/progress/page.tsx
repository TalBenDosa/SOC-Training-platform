"use client";
/**
 * Progress v2: the learner's own record. Six tabs answer five questions in under a
 * minute: what did I do, where did I err, what should I strengthen, how fast do I
 * respond, and what did my reports say.
 * Spec: claude-work/research/progress-redesign/SPEC-progress-self-tracking.md
 *
 * The numbers come from /api/me/progress (server-side, the learner's own rows in their
 * current organisation only) and use the same engine as the instructor's student page.
 * XP, rank and streak still come from the storage facade so they always match the
 * Topbar. A guest (not signed in) sees XP and streak, and a prompt to sign in.
 */
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Award, Flame, Loader2, Snowflake, Star, AlertTriangle, ChevronDown } from "lucide-react";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/utils";
import { rankForXp, nextRank, rankProgress } from "@/lib/progression/ranks";
import { computeStreak, collectActivityDates } from "@/lib/progression/streak";
import {
  getTotalXp, getScenarioHistory, getRoomProgress, getDashboardSessions, getClearedCompanies,
  broadcastXpChanged, getQuizActivityDates, getLessonActivityDates,
  getStreakFreezeDates as facadeGetStreakFreezes, saveStreakFreezeDates as facadeSaveStreakFreezes,
} from "@/lib/storage/progress";
import { useProgressSnapshot } from "@/lib/storage/useProgressSnapshot";
import type { ProgressPayload } from "@/lib/progress/selfView";
import { OverviewTab } from "@/components/progress/OverviewTab";
import { ActivityTab } from "@/components/progress/ActivityTab";
import { MistakesTab } from "@/components/progress/MistakesTab";
import { TopicsTab } from "@/components/progress/TopicsTab";
import { ResponseTab } from "@/components/progress/ResponseTab";
import { ReportsTab } from "@/components/progress/ReportsTab";

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "activity", label: "Activity" },
  { key: "mistakes", label: "Mistakes" },
  { key: "topics", label: "Topics" },
  { key: "response", label: "Response time" },
  { key: "reports", label: "Reports" },
] as const;
type TabKey = (typeof TABS)[number]["key"];
const isTab = (v: string | null): v is TabKey => TABS.some(t => t.key === v);

// Duolingo-style grace: up to this many freezes a month can cover yesterday.
const STREAK_FREEZES_PER_MONTH = 2;

export default function ProgressPage() {
  const { ready, version, slow, failed } = useProgressSnapshot();
  const [tab, setTab] = useState<TabKey>("overview");
  const [payload, setPayload] = useState<ProgressPayload | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "guest" | "error">("loading");
  const [errMsg, setErrMsg] = useState<string | null>(null);

  // Facade-backed: XP, streak, freezes (identical to the Topbar), and the badges' inputs.
  const [totalXp, setTotalXp] = useState(0);
  const [activityDates, setActivityDates] = useState<string[]>([]);
  const [freezeDates, setFreezeDates] = useState<string[]>([]);
  const [badgeInputs, setBadgeInputs] = useState({ caught: false, scenarios: 0, cleared: 0, sharp: false });

  // Deep link: /progress?tab=mistakes (end-of-scenario links, the "Review" next step).
  useEffect(() => {
    const t = new URLSearchParams(window.location.search).get("tab");
    if (isTab(t)) setTab(t);
  }, []);
  const choose = useCallback((t: TabKey) => {
    setTab(t);
    const url = new URL(window.location.href);
    if (t === "overview") url.searchParams.delete("tab"); else url.searchParams.set("tab", t);
    window.history.replaceState(null, "", url.toString());
  }, []);

  const load = useCallback(() => {
    setState("loading"); setErrMsg(null);
    fetch("/api/me/progress", { cache: "no-store" })
      .then(async r => {
        if (r.status === 401) { setState("guest"); return; }
        const body = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(body.error ?? "Couldn't load your progress.");
        setPayload(body as ProgressPayload); setState("ready");
      })
      .catch(e => { setErrMsg(e instanceof Error ? e.message : "Couldn't load your progress."); setState("error"); });
  }, []);
  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!ready) return;
    setTotalXp(getTotalXp());
    const cutoff = Date.now() - 30 * 86_400_000;
    const freezes = facadeGetStreakFreezes().filter(d => new Date(d).getTime() >= cutoff);
    setFreezeDates(freezes);
    let roomDates: string[] = [];
    try { roomDates = Object.values(getRoomProgress() as Record<string, { completedAt?: string }>).map(r => r.completedAt).filter((d): d is string => !!d); } catch { /* corrupt local data */ }
    const scenarios = (() => { try { return getScenarioHistory(); } catch { return []; } })();
    const sessions = (() => { try { return getDashboardSessions() as unknown as { date: string; detectRate: number; attacksCaughtCount?: number }[]; } catch { return []; } })();
    let quizLesson: string[] = [];
    try { quizLesson = [...getQuizActivityDates(), ...getLessonActivityDates()]; } catch { /* ignore */ }
    setActivityDates(collectActivityDates({
      scenarioDates: scenarios.map(s => s.date), dashboardDates: sessions.map(s => s.date), roomDates, quizDates: quizLesson, freezeDates: freezes,
    }));
    let cleared = 0; try { cleared = getClearedCompanies().length; } catch { /* ignore */ }
    setBadgeInputs({ caught: sessions.some(s => (s.attacksCaughtCount ?? 0) >= 1), scenarios: scenarios.length, cleared, sharp: sessions.some(s => s.detectRate >= 80) });
  }, [ready, version]);

  const streak = computeStreak(activityDates);
  const daySet = new Set(activityDates.map(d => new Date(d).toDateString()));
  const yesterday = new Date(); yesterday.setDate(yesterday.getDate() - 1);
  const twoDaysAgo = new Date(); twoDaysAgo.setDate(twoDaysAgo.getDate() - 2);
  const hasToday = daySet.has(new Date().toDateString());
  const freezesLeft = Math.max(0, STREAK_FREEZES_PER_MONTH - freezeDates.length);
  const streakAtRisk = streak > 0 && !hasToday;
  const canUseFreeze = streak === 0 && !hasToday && !daySet.has(yesterday.toDateString()) && daySet.has(twoDaysAgo.toDateString()) && freezesLeft > 0;
  const applyFreeze = () => {
    const updated = [...freezeDates, yesterday.toISOString()];
    setFreezeDates(updated); facadeSaveStreakFreezes(updated);
    setActivityDates(d => [...d, yesterday.toISOString()]);
    broadcastXpChanged();
  };

  return (
    <div>
      <Topbar title="My Progress" subtitle="What you did, where you erred, what to strengthen" />
      <div className="container mx-auto max-w-[1200px] space-y-4 px-4 pb-24 pt-4 sm:px-6 sm:pt-6">
        {failed.length > 0 && (
          <div role="alert" className="flex items-center gap-3 rounded-lg border border-severity-high/40 bg-severity-high/5 px-4 py-3">
            <AlertTriangle aria-hidden="true" className="h-4 w-4 shrink-0 text-severity-high" />
            <p className="flex-1 text-sm text-slate-200">Part of your progress couldn&apos;t be loaded, so your XP or streak may be incomplete. Nothing is lost.</p>
            <button onClick={() => window.location.reload()} className="shrink-0 rounded-md border border-severity-high/50 bg-severity-high/15 px-3 py-1.5 text-xs font-bold text-severity-high">Reload</button>
          </div>
        )}

        <RankStrip xp={totalXp} ready={ready} slow={slow} streak={streak} />

        {streakAtRisk && (
          <p className="flex items-center gap-2 rounded-lg border border-severity-medium/40 bg-severity-medium/5 px-4 py-2.5 text-sm text-slate-200">
            <Flame aria-hidden="true" className="h-4 w-4 shrink-0 text-severity-medium" />
            Your {streak}-day streak is still alive. Do a room, quiz, scenario or shift today to keep it.
          </p>
        )}
        {canUseFreeze && (
          <div className="flex flex-wrap items-center gap-3 rounded-lg border border-cyber-500/40 bg-cyber-500/5 px-4 py-2.5">
            <Snowflake aria-hidden="true" className="h-4 w-4 shrink-0 text-cyber-300" />
            <p className="flex-1 text-sm text-slate-200">Yesterday got away from you. A streak freeze covers it. {freezesLeft} left this month.</p>
            <button onClick={applyFreeze} className="shrink-0 rounded-md border border-cyber-500/50 bg-cyber-500/15 px-3 py-1.5 text-xs font-bold text-cyber-300">Use a freeze</button>
          </div>
        )}

        {/* Tabs: a horizontally scrolling chip row on phones, sticky under the top bar. */}
        <div className="sticky top-0 z-10 -mx-4 border-b border-border bg-bg/95 px-4 backdrop-blur sm:-mx-6 sm:px-6">
          <div role="tablist" aria-label="Progress sections" className="flex gap-1 overflow-x-auto py-2 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
            onKeyDown={e => {
              if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
              const i = TABS.findIndex(t => t.key === tab);
              const n = TABS[(i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length].key;
              choose(n); document.getElementById(`tab-${n}`)?.focus();
            }}>
            {TABS.map(t => (
              <button key={t.key} id={`tab-${t.key}`} role="tab" type="button" aria-selected={tab === t.key} aria-controls="progress-panel" tabIndex={tab === t.key ? 0 : -1}
                onClick={() => choose(t.key)}
                className={cn("shrink-0 whitespace-nowrap rounded-full border px-3 py-1.5 text-xs font-semibold transition-colors",
                  tab === t.key ? "border-cyber-500/60 bg-cyber-500/15 text-cyber-300" : "border-border bg-bg-elevated text-slate-300 hover:bg-bg-hover")}>
                {t.label}
                {t.key === "mistakes" && payload && payload.criticalMisses.length > 0 && <span className="ml-1.5 rounded-full bg-severity-high/20 px-1.5 text-[10px] text-severity-high">{payload.criticalMisses.length}</span>}
              </button>
            ))}
          </div>
        </div>

        <div id="progress-panel" role="tabpanel" aria-labelledby={`tab-${tab}`}>
          {state === "loading" && (
            <Card className="flex items-center gap-3" aria-busy="true">
              <Loader2 aria-hidden="true" className="h-5 w-5 animate-spin text-cyber-300" />
              <p className="text-sm text-slate-300">Loading your progress…</p>
            </Card>
          )}
          {state === "error" && (
            <Card className="flex flex-wrap items-center gap-3 border-severity-high/40">
              <p className="flex-1 text-sm text-slate-200">{errMsg} Your saved progress is not lost.</p>
              <button onClick={load} className="rounded-md border border-severity-high/50 bg-severity-high/15 px-3 py-1.5 text-xs font-bold text-severity-high">Try again</button>
            </Card>
          )}
          {state === "guest" && (
            <Card>
              <p className="text-sm font-semibold text-white">Sign in to see your full progress</p>
              <p className="mt-1 text-sm text-slate-400">Your mistakes, topics, response times and reports are saved to your account. Sign in to see them here.</p>
              <Link href="/login" className="mt-3 inline-block rounded-md border border-cyber-500/40 bg-cyber-500/10 px-3 py-1.5 text-xs font-semibold text-cyber-300">Sign in</Link>
            </Card>
          )}
          {state === "ready" && payload && (
            <>
              {tab === "overview" && <OverviewTab data={payload} />}
              {tab === "activity" && <ActivityTab data={payload.activity} />}
              {tab === "mistakes" && <MistakesTab critical={payload.criticalMisses} />}
              {tab === "topics" && <TopicsTab data={payload.skills} />}
              {tab === "response" && <ResponseTab data={payload.response} />}
              {tab === "reports" && <ReportsTab data={payload.reports} />}
            </>
          )}
        </div>

        {tab === "overview" && <BadgesAndClass xp={totalXp} inputs={badgeInputs} />}
      </div>
    </div>
  );
}

/** XP, rank and streak in one line (the full ladder and certificates live on /achievements). */
function RankStrip({ xp, ready, slow, streak }: { xp: number; ready: boolean; slow: boolean; streak: number }) {
  const rank = rankForXp(xp); const next = nextRank(xp); const prog = rankProgress(xp);
  return (
    <Card className="flex flex-wrap items-center gap-x-4 gap-y-2 py-3" padded={false}>
      <div className="flex items-center gap-3 pl-4">
        <div className={cn("flex h-10 w-10 items-center justify-center rounded-full border-2 bg-cyber-500/10 text-xl font-bold", rank.accent.ring, rank.accent.text)} aria-hidden="true">{rank.glyph}</div>
        <div>
          <p className={cn("text-[10px] font-semibold uppercase tracking-widest", rank.accent.text)}>{rank.label}{rank.tier.startsWith("tier-") ? ` · ${rank.tier.replace("tier-", "Tier ")}` : ""}</p>
          <p className="flex items-center gap-1.5 font-mono text-lg font-bold text-white">
            <Star aria-hidden="true" className="h-4 w-4 text-severity-medium" />
            {ready ? `${xp.toLocaleString()} XP` : slow ? "Still loading…" : "…"}
          </p>
        </div>
      </div>
      {prog && next && (
        <div className="min-w-[160px] flex-1 px-4 sm:px-0">
          <div className="h-1.5 overflow-hidden rounded-full bg-bg"><div className={cn("h-full rounded-full", rank.accent.bar)} style={{ width: `${prog.pct}%` }} /></div>
          <p className="mt-1 text-[11px] text-slate-400">{(next.minXp - xp).toLocaleString()} XP to {next.label}</p>
        </div>
      )}
      <div className="flex items-center gap-4 px-4">
        <span className="flex items-center gap-1.5 text-sm text-slate-200"><Flame aria-hidden="true" className="h-4 w-4 text-severity-medium" />{streak} day{streak === 1 ? "" : "s"}</span>
        <Link href="/achievements" className="text-xs font-semibold text-cyber-300 hover:text-cyber-200">Achievements →</Link>
      </div>
    </Card>
  );
}

type LeaderRow = { rank: number; displayName: string; xp: number; level: number; isMe: boolean };

/** Badges (derived, no storage) and, for an enrolled class, the cohort leaderboard. */
function BadgesAndClass({ xp, inputs }: { xp: number; inputs: { caught: boolean; scenarios: number; cleared: number; sharp: boolean } }) {
  const [rows, setRows] = useState<LeaderRow[]>([]);
  useEffect(() => {
    let alive = true;
    fetch("/api/leaderboard").then(r => (r.ok ? r.json() : { rows: [], available: false }))
      .then(d => { if (alive) setRows(d.available ? d.rows : []); }).catch(() => {});
    return () => { alive = false; };
  }, []);
  const badges = [
    { name: "First Login", tier: "bronze", desc: "Logged in for the first time", on: true },
    { name: "First Blood", tier: "bronze", desc: "Caught your first attack in the live feed", on: inputs.caught },
    { name: "Scenario Rookie", tier: "bronze", desc: "Completed your first full scenario", on: inputs.scenarios >= 1 },
    { name: "Company Secured", tier: "silver", desc: "Passed an incident report and secured a company", on: inputs.cleared >= 1 },
    { name: "Portfolio Defender", tier: "gold", desc: "Secured 3 or more companies", on: inputs.cleared >= 3 },
    { name: "Sharp Eye", tier: "silver", desc: "Caught 80%+ of the attacks in a shift", on: inputs.sharp },
    { name: "Made Analyst", tier: "gold", desc: "Reached the Analyst rank (Tier 1)", on: rankForXp(xp).minXp >= 5000 },
  ].filter(b => b.on);
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <details className="group rounded-lg border border-border bg-bg-elevated/60">
        <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-3">
          <span className="flex items-center gap-2 text-sm font-semibold text-white"><Award aria-hidden="true" className="h-4 w-4 text-severity-medium" /> Badges ({badges.length})</span>
          <ChevronDown aria-hidden="true" className="h-4 w-4 text-slate-400 transition-transform group-open:rotate-180" />
        </summary>
        <ul className="space-y-1.5 px-4 pb-4">
          {badges.map(b => (
            <li key={b.name} className="flex items-center gap-3 rounded border border-border bg-bg px-3 py-2">
              <Award aria-hidden="true" className={cn("h-4 w-4 shrink-0", b.tier === "gold" ? "text-severity-medium" : b.tier === "silver" ? "text-slate-300" : "text-cyber-400")} />
              <div className="min-w-0"><p className="text-xs font-semibold text-slate-100">{b.name}</p><p className="text-[11px] text-slate-400">{b.desc}</p></div>
              <span className="ml-auto text-[10px] uppercase text-slate-400">{b.tier}</span>
            </li>
          ))}
        </ul>
      </details>
      {rows.length > 0 && (
        <Card padded={false}>
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <h3 className="text-sm font-semibold text-white">Class leaderboard</h3>
            <span className="text-[10px] uppercase tracking-wider text-slate-400">Your cohort</span>
          </div>
          <ul>
            {rows.map(r => (
              <li key={`${r.rank}-${r.displayName}`} className={cn("flex items-center gap-3 border-b border-border/60 px-4 py-2 last:border-b-0", r.isMe && "bg-cyber-500/5")}>
                <span className="w-6 text-center font-mono text-[11px] text-slate-400">{r.rank}</span>
                <span className={cn("min-w-0 flex-1 truncate text-xs", r.isMe ? "font-semibold text-cyber-300" : "text-slate-200")}><bdi>{r.displayName}</bdi>{r.isMe && " (you)"}</span>
                <span className="font-mono text-xs text-cyber-300">{r.xp.toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
