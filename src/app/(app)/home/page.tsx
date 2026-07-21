"use client";
/**
 * The learner's landing page.
 *
 * Before this, signing in dropped a student straight onto /rooms — a list of 83
 * rooms with no orientation, no indication of where they had got to, and no
 * acknowledgement that they are a specific person with a history. The first
 * screen after login is the one that answers "where am I and what now", and it
 * was answering neither.
 *
 * Everything here is derived from progress the learner has actually earned. No
 * placeholder numbers: if nothing has been completed, the page says so plainly
 * and points at a first step rather than showing an empty dashboard.
 */
import Link from "next/link";
import { useEffect, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/lib/auth/AuthContext";
import { useRank } from "@/lib/progression/useRank";
import { RANKS } from "@/lib/progression/ranks";
import { getRoomProgress, getScenarioHistory } from "@/lib/storage/progress";
import { ROOMS } from "@/data/rooms";
import { BUILTIN_LESSONS } from "@/data/builtinLessons";
import { DoorOpen, Target, BookOpen, TrendingUp, Trophy } from "lucide-react";

export default function HomePage() {
  const { user } = useAuth();
  const { xp, rank, next, progress, ready } = useRank();

  const [roomsDone, setRoomsDone] = useState(0);
  const [scenariosDone, setScenariosDone] = useState(0);

  // Read after mount only — these come from the storage backend, which differs
  // between server and client and would hydrate-mismatch if read during render.
  useEffect(() => {
    const rp = getRoomProgress();
    // `completedAt` is the real completion marker — a room with progress but no
    // completedAt is started, not finished, and counting it would tell the
    // learner they had done work they had not.
    setRoomsDone(Object.values(rp).filter(r => Boolean(r?.completedAt)).length);
    setScenariosDone(getScenarioHistory().length);
  }, []);

  // The name the learner recognises. Supabase gives us an email; the local part
  // is the closest thing to a name we hold without asking for one.
  const displayName = user?.email?.split("@")[0] ?? "analyst";
  const isNew = roomsDone === 0 && scenariosDone === 0 && xp === 0;

  return (
    <div>
      <Topbar title="Home" />

      <main className="container mx-auto max-w-5xl px-6 py-8 space-y-6">

        {/* ── Welcome + rank ─────────────────────────────────────────── */}
        <Card className="p-6">
          <p className="text-sm text-slate-400">Welcome back,</p>
          <h1 className="mt-1 text-2xl font-bold text-white">{displayName}</h1>

          {ready && (
            <div className="mt-5">
              <div className="flex items-baseline justify-between gap-4">
                <div>
                  <span className="text-sm font-semibold text-cyber-300">{rank.label}</span>
                  <span className="ml-2 font-mono text-[11px] text-slate-500">{rank.tier}</span>
                </div>
                <span className="font-mono text-2xl font-bold text-white">
                  {xp.toLocaleString()} <span className="text-sm font-normal text-slate-500">XP</span>
                </span>
              </div>

              <p className="mt-2 text-xs leading-relaxed text-slate-400">{rank.blurb}</p>

              {/* Progress toward the next rank. Hidden at the top of the ladder,
                  where a full bar reads as a stalled loader rather than an
                  achievement — same reasoning as the Topbar chip. */}
              {progress && next ? (
                <div className="mt-4">
                  <div className="h-2 w-full overflow-hidden rounded-full bg-slate-700/60">
                    <div
                      className="h-full rounded-full bg-cyber-400 transition-[width] duration-700"
                      style={{ width: `${progress.pct}%` }}
                    />
                  </div>
                  <p className="mt-2 text-xs text-slate-500">
                    {(next.minXp - xp).toLocaleString()} XP to {next.label}
                    <span className="font-mono text-slate-600"> · {next.tier}</span>
                  </p>
                </div>
              ) : (
                <p className="mt-4 flex items-center gap-2 text-xs text-neon-green">
                  <Trophy className="h-3.5 w-3.5" /> Top rank reached.
                </p>
              )}
            </div>
          )}
        </Card>

        {/* ── What you've done ───────────────────────────────────────── */}
        <div className="grid gap-4 sm:grid-cols-3">
          <Stat icon={<BookOpen className="h-4 w-4" />} label="Rooms completed" value={`${roomsDone} / ${ROOMS.length}`} />
          <Stat icon={<Target className="h-4 w-4" />}   label="Scenarios solved" value={String(scenariosDone)} />
          <Stat icon={<TrendingUp className="h-4 w-4" />} label="Lessons available" value={String(BUILTIN_LESSONS.length)} />
        </div>

        {/* ── Where to go ────────────────────────────────────────────── */}
        <Card className="p-6">
          <h2 className="text-sm font-semibold text-white">
            {isNew ? "Start here" : "Continue"}
          </h2>
          <p className="mt-1 text-xs text-slate-400">
            {isNew
              ? "Rooms teach a concept and then make you use it. Start with the foundations — they assume nothing."
              : "Rooms build the concepts, scenarios make you reconstruct a real intrusion and write it up."}
          </p>
          <div className="mt-4 flex flex-wrap gap-3">
            <Link href="/rooms">
              <Button variant="primary"><BookOpen className="mr-2 h-4 w-4" /> Learning rooms</Button>
            </Link>
            <Link href="/scenarios">
              <Button variant="outline"><Target className="mr-2 h-4 w-4" /> Investigation scenarios</Button>
            </Link>
            <Link href="/dashboard">
              <Button variant="outline"><DoorOpen className="mr-2 h-4 w-4" /> Live SOC dashboard</Button>
            </Link>
          </div>
        </Card>

        {/* ── The ladder, so the number means something ───────────────── */}
        <Card className="p-6">
          <h2 className="text-sm font-semibold text-white">Analyst ranks</h2>
          <p className="mt-1 text-xs text-slate-400">
            These mirror a real SOC career path. XP comes from rooms, lessons, quizzes and scenarios.
          </p>
          <ul className="mt-4 space-y-2">
            {RANKS.map(r => {
              const held = ready && xp >= r.minXp;
              const current = ready && rank.id === r.id;
              return (
                <li
                  key={r.id}
                  className={`flex items-center justify-between rounded border px-3 py-2 text-xs ${
                    current
                      ? "border-cyber-500/50 bg-cyber-500/10 text-white"
                      : held
                        ? "border-border bg-bg text-slate-300"
                        : "border-border/50 bg-bg text-slate-500"
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <span className="font-semibold">{r.label}</span>
                    <span className="font-mono text-[10px] text-slate-500">{r.tier}</span>
                    {current && <span className="text-[10px] text-cyber-300">— you are here</span>}
                  </span>
                  <span className="font-mono">{r.minXp.toLocaleString()} XP</span>
                </li>
              );
            })}
          </ul>
        </Card>
      </main>
    </div>
  );
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 text-slate-400">{icon}<span className="text-xs">{label}</span></div>
      <p className="mt-2 font-mono text-xl font-bold text-white">{value}</p>
    </Card>
  );
}
