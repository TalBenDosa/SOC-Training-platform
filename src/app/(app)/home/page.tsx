"use client";
/**
 * The learner's landing page.
 *
 * Signing in used to drop a student straight onto /rooms — 83 rooms, no
 * orientation, no sense of where they had got to. The first screen after login
 * answers "where am I and what now", and it was answering neither.
 *
 * GAMIFICATION RULE FOR THIS PAGE: every element is driven by progress the
 * learner actually earned. The platform already removed a fake leaderboard and
 * a set of decorative controls that did nothing when clicked, because a widget
 * that looks like feedback but is not teaches people to distrust the real
 * feedback next to it. So: no invented rivals, no vanity counters, no locked
 * achievement that cannot be unlocked. A brand-new account gets an honest
 * "start here", not an empty dashboard pretending to hold data.
 */
import Link from "next/link";
import { useEffect, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth/AuthContext";
import { useRank } from "@/lib/progression/useRank";
import { RANKS } from "@/lib/progression/ranks";
import { computeStreak, streakAtRisk } from "@/lib/progression/streak";
import {
  getRoomProgress, getScenarioHistory, getClearedCompanies, getDashboardSessions,
} from "@/lib/storage/progress";
import { ROOMS } from "@/data/rooms";
import { SCENARIOS } from "@/lib/sim/scenarios";
import {
  DoorOpen, Target, BookOpen, Flame, Trophy, Lock, Check, ChevronRight, Zap,
} from "lucide-react";

interface Achievement {
  id: string;
  name: string;
  desc: string;
  earned: boolean;
  /** Shown on locked achievements so the goal is concrete, never vague. */
  progress?: string;
}

export default function HomePage() {
  const { user } = useAuth();
  const { xp, rank, next, progress, ready } = useRank();

  const [roomsDone, setRoomsDone]   = useState(0);
  const [scenarios, setScenarios]   = useState<{ score: number }[]>([]);
  const [streak, setStreak]         = useState(0);
  const [atRisk, setAtRisk]         = useState(false);
  const [companies, setCompanies]   = useState(0);
  const [caughtAny, setCaughtAny]   = useState(false);
  const [loaded, setLoaded]         = useState(false);

  // Read after mount only: these come from the storage backend, which differs
  // between server and client and would hydrate-mismatch if read during render.
  useEffect(() => {
    const rp = getRoomProgress();
    // `completedAt` is the completion marker. A room with progress but no
    // completedAt is started, not finished — counting it would tell the learner
    // they had done work they had not.
    const roomDates = Object.values(rp).map(r => r.completedAt).filter((d): d is string => !!d);
    setRoomsDone(roomDates.length);

    const hist = getScenarioHistory();
    setScenarios(hist.map(h => ({ score: h.score })));

    const activity = [...roomDates, ...hist.map(h => h.date)];
    setStreak(computeStreak(activity));
    setAtRisk(streakAtRisk(activity));

    setCompanies(getClearedCompanies().length);
    setCaughtAny(getDashboardSessions().some(s => ((s as { attacksCaughtCount?: number }).attacksCaughtCount ?? 0) >= 1));
    setLoaded(true);
  }, []);

  const displayName = user?.email?.split("@")[0] ?? "analyst";
  const avgScore = scenarios.length
    ? Math.round(scenarios.reduce((s, r) => s + r.score, 0) / scenarios.length)
    : null;
  const isNew = loaded && roomsDone === 0 && scenarios.length === 0 && xp === 0;

  // Achievements. Each locked one carries its own distance, so it reads as a
  // target rather than a tease.
  const achievements: Achievement[] = [
    { id: "first-room",  name: "First Room",      desc: "Finish your first learning room",
      earned: roomsDone >= 1,  progress: roomsDone >= 1 ? undefined : "0 of 1" },
    { id: "first-case",  name: "First Case",      desc: "Solve a full investigation scenario",
      earned: scenarios.length >= 1, progress: scenarios.length >= 1 ? undefined : "0 of 1" },
    { id: "first-catch", name: "First Catch",     desc: "Catch a live attack on the SOC dashboard",
      earned: caughtAny,       progress: caughtAny ? undefined : "not yet" },
    { id: "ten-rooms",   name: "Ten Rooms",       desc: "Finish ten learning rooms",
      earned: roomsDone >= 10, progress: roomsDone >= 10 ? undefined : `${roomsDone} of 10` },
    { id: "five-cases",  name: "Case Load",       desc: "Solve five investigation scenarios",
      earned: scenarios.length >= 5, progress: scenarios.length >= 5 ? undefined : `${scenarios.length} of 5` },
    { id: "sharp",       name: "Sharp Report",    desc: "Average 80 or better across your scenarios",
      earned: avgScore !== null && avgScore >= 80,
      progress: avgScore === null ? "no scenarios yet" : avgScore >= 80 ? undefined : `averaging ${avgScore}` },
    { id: "company",     name: "Company Secured", desc: "Pass an incident report and secure a company",
      earned: companies >= 1,  progress: companies >= 1 ? undefined : "0 of 1" },
    { id: "week",        name: "Seven Days",      desc: "Keep a seven-day streak",
      earned: streak >= 7,     progress: streak >= 7 ? undefined : `${streak} of 7` },
  ];
  const earnedCount = achievements.filter(a => a.earned).length;

  return (
    <div>
      <Topbar title="Home" />

      <main className="container mx-auto max-w-5xl px-6 py-8 space-y-5">

        {/* ── Rank hero ──────────────────────────────────────────────── */}
        <Card className={cn("relative overflow-hidden p-6 ring-1 transition-shadow", ready && rank.accent.ring, ready && `shadow-lg ${rank.accent.glow}`)}>
          <div className="pointer-events-none absolute -right-10 -top-10 h-40 w-40 rounded-full bg-cyber-500/5 blur-2xl" />

          <div className="relative flex flex-col gap-5 sm:flex-row sm:items-center">
            {/* Medallion */}
            <div className={cn(
              "flex h-20 w-20 shrink-0 items-center justify-center rounded-2xl bg-bg-elevated text-4xl ring-2",
              ready ? `${rank.accent.ring} ${rank.accent.text}` : "ring-border text-slate-600",
            )}>
              {ready ? rank.glyph : "·"}
            </div>

            <div className="min-w-0 flex-1">
              <p className="text-sm text-slate-400">Welcome back,</p>
              <h1 className="truncate text-2xl font-bold text-white">{displayName}</h1>

              {ready && (
                <div className="mt-2 flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <span className={cn("text-lg font-bold", rank.accent.text)}>{rank.label}</span>
                  <span className="font-mono text-[11px] text-slate-500">{rank.tier}</span>
                  <span className="ml-auto font-mono text-2xl font-bold text-white">
                    {xp.toLocaleString()}<span className="ml-1 text-sm font-normal text-slate-500">XP</span>
                  </span>
                </div>
              )}
            </div>
          </div>

          {ready && (
            <div className="relative mt-5">
              {progress && next ? (
                <>
                  <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-800">
                    <div
                      className={cn("h-full rounded-full transition-[width] duration-1000 ease-out", rank.accent.bar)}
                      style={{ width: `${progress.pct}%` }}
                    />
                  </div>
                  <div className="mt-2 flex items-center justify-between text-xs">
                    <span className="text-slate-500">{rank.blurb.split(".")[0]}.</span>
                    <span className="shrink-0 pl-3 font-medium text-slate-300">
                      <span className={rank.accent.text}>{(next.minXp - xp).toLocaleString()} XP</span> to {next.label}
                    </span>
                  </div>
                </>
              ) : (
                <p className="flex items-center gap-2 text-sm font-medium text-neon-amber">
                  <Trophy className="h-4 w-4" /> Top rank reached — {rank.blurb.split(".")[0]}.
                </p>
              )}
            </div>
          )}
        </Card>

        {/* ── Streak + counters ──────────────────────────────────────── */}
        <div className="grid gap-4 sm:grid-cols-4">
          <Card className={cn("p-4", atRisk && "ring-1 ring-neon-amber/40")}>
            <div className="flex items-center gap-2 text-slate-400">
              <Flame className={cn("h-4 w-4", streak > 0 ? "text-neon-amber" : "text-slate-600")} />
              <span className="text-xs">Day streak</span>
            </div>
            <p className="mt-2 font-mono text-2xl font-bold text-white">{loaded ? streak : "–"}</p>
            {/* Only nudge when there is genuinely something to lose today. */}
            {atRisk && <p className="mt-1 text-[11px] text-neon-amber">Do one thing today to keep it.</p>}
          </Card>

          <Counter icon={<BookOpen className="h-4 w-4" />} label="Rooms" value={loaded ? `${roomsDone}` : "–"} sub={`of ${ROOMS.length}`} />
          <Counter icon={<Target className="h-4 w-4" />}   label="Scenarios" value={loaded ? `${scenarios.length}` : "–"} sub={`of ${SCENARIOS.length}`} />
          <Counter icon={<Zap className="h-4 w-4" />}      label="Avg score" value={avgScore === null ? "–" : `${avgScore}`} sub={avgScore === null ? "no cases yet" : "across your cases"} />
        </div>

        {/* ── Next step ──────────────────────────────────────────────── */}
        <Card className="p-6">
          <h2 className="text-sm font-semibold text-white">{isNew ? "Start here" : "Pick up where you left off"}</h2>
          <p className="mt-1 text-xs text-slate-400">
            {isNew
              ? "Rooms teach a concept and then make you use it. The foundations assume nothing — start there."
              : "Rooms build the concepts. Scenarios make you reconstruct a real intrusion from its logs and write it up."}
          </p>
          <div className="mt-4 flex flex-wrap gap-3">
            <Link href="/rooms"><Button variant="primary"><BookOpen className="mr-2 h-4 w-4" /> Learning rooms</Button></Link>
            <Link href="/scenarios"><Button variant="outline"><Target className="mr-2 h-4 w-4" /> Investigations</Button></Link>
            <Link href="/dashboard"><Button variant="outline"><DoorOpen className="mr-2 h-4 w-4" /> Live SOC</Button></Link>
          </div>
        </Card>

        {/* ── Achievements ───────────────────────────────────────────── */}
        <Card className="p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Achievements</h2>
            <span className="font-mono text-xs text-slate-500">{loaded ? `${earnedCount} / ${achievements.length}` : "–"}</span>
          </div>
          <div className="mt-4 grid gap-2 sm:grid-cols-2">
            {achievements.map(a => (
              <div
                key={a.id}
                className={cn(
                  "flex items-start gap-3 rounded-lg border px-3 py-2.5 transition-colors",
                  a.earned ? "border-neon-green/30 bg-neon-green/5" : "border-border bg-bg",
                )}
              >
                <span className={cn(
                  "mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full",
                  a.earned ? "bg-neon-green/15 text-neon-green" : "bg-slate-800 text-slate-600",
                )}>
                  {a.earned ? <Check className="h-3.5 w-3.5" /> : <Lock className="h-3 w-3" />}
                </span>
                <div className="min-w-0">
                  <p className={cn("text-xs font-semibold", a.earned ? "text-white" : "text-slate-400")}>{a.name}</p>
                  <p className="text-[11px] leading-snug text-slate-500">{a.desc}</p>
                  {a.progress && <p className="mt-0.5 font-mono text-[10px] text-slate-600">{a.progress}</p>}
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* ── The ladder ─────────────────────────────────────────────── */}
        <Card className="p-6">
          <h2 className="text-sm font-semibold text-white">Analyst ranks</h2>
          <p className="mt-1 text-xs text-slate-400">
            These mirror a real SOC career path. XP comes from rooms, lessons, quizzes and scenarios.
          </p>
          <ul className="mt-4 space-y-1.5">
            {RANKS.map(r => {
              const held    = ready && xp >= r.minXp;
              const current = ready && rank.id === r.id;
              return (
                <li key={r.id} className={cn(
                  "flex items-center gap-3 rounded-lg border px-3 py-2 text-xs",
                  current ? `border-transparent bg-bg-elevated ring-1 ${r.accent.ring}`
                          : held ? "border-border bg-bg" : "border-border/40 bg-bg opacity-60",
                )}>
                  <span className={cn("text-base", held ? r.accent.text : "text-slate-700")}>{r.glyph}</span>
                  <span className={cn("font-semibold", held ? "text-white" : "text-slate-500")}>{r.label}</span>
                  <span className="font-mono text-[10px] text-slate-500">{r.tier}</span>
                  {current && <ChevronRight className={cn("h-3.5 w-3.5", r.accent.text)} />}
                  {current && <span className={cn("text-[10px] font-medium", r.accent.text)}>you are here</span>}
                  <span className="ml-auto font-mono text-slate-500">{r.minXp.toLocaleString()} XP</span>
                </li>
              );
            })}
          </ul>
        </Card>
      </main>
    </div>
  );
}

function Counter({ icon, label, value, sub }: { icon: React.ReactNode; label: string; value: string; sub: string }) {
  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 text-slate-400">{icon}<span className="text-xs">{label}</span></div>
      <p className="mt-2 font-mono text-2xl font-bold text-white">{value}</p>
      <p className="mt-0.5 text-[11px] text-slate-600">{sub}</p>
    </Card>
  );
}
