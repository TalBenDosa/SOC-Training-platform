"use client";
/**
 * The screen a learner lands on straight after signing in.
 *
 * Deliberately small: a greeting by name, the score, and the badge they hold.
 * An earlier version of this page carried streaks, achievement grids and a
 * full rank ladder — that belongs on /progress, which already exists for it.
 * The moment after sign-in should tell you who you are and where you stand,
 * then get out of the way.
 */
import Link from "next/link";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth/AuthContext";
import { useRank } from "@/lib/progression/useRank";
import { BookOpen, Target } from "lucide-react";

export default function HomePage() {
  const { user } = useAuth();
  const { xp, rank, ready } = useRank();

  // The closest thing to a name we hold without asking for one.
  const name = user?.email?.split("@")[0] ?? "analyst";

  return (
    <div>
      <Topbar title="Home" />

      <main className="container mx-auto flex max-w-2xl flex-col items-center px-6 py-16 text-center">

        <p className="text-lg text-slate-300">
          Hello <span className="font-semibold text-white">{name}</span>
        </p>
        <h1 className="mt-2 text-3xl font-bold text-white">
          Welcome to <span className="text-cyber-300">Hack The SOC</span>
        </h1>

        {/* ── Score + badge ──────────────────────────────────────────── */}
        <Card className={cn(
          "mt-10 w-full p-8 ring-1 transition-shadow",
          ready ? `${rank.accent.ring} shadow-lg ${rank.accent.glow}` : "ring-border",
        )}>
          <div className="flex flex-col items-center gap-6 sm:flex-row sm:justify-center sm:gap-12">

            {/* Score */}
            <div>
              <p className="text-xs uppercase tracking-widest text-slate-500">Score</p>
              <p className="mt-1 font-mono text-4xl font-bold text-white">
                {ready ? xp.toLocaleString() : "–"}
                <span className="ml-1.5 text-base font-normal text-slate-500">XP</span>
              </p>
            </div>

            <div className="hidden h-16 w-px bg-border sm:block" />

            {/* Badge */}
            <div className="flex items-center gap-3">
              <span className={cn(
                "flex h-14 w-14 items-center justify-center rounded-xl bg-bg-elevated text-3xl ring-2",
                ready ? `${rank.accent.ring} ${rank.accent.text}` : "ring-border text-slate-600",
              )}>
                {ready ? rank.glyph : "·"}
              </span>
              <div className="text-left">
                <p className="text-xs uppercase tracking-widest text-slate-500">Badge</p>
                <p className={cn("mt-0.5 text-xl font-bold", ready ? rank.accent.text : "text-slate-500")}>
                  {ready ? rank.label : "–"}
                </p>
                <p className="font-mono text-[11px] text-slate-500">{ready ? rank.tier : ""}</p>
              </div>
            </div>
          </div>
        </Card>

        <div className="mt-8 flex flex-wrap justify-center gap-3">
          <Link href="/rooms"><Button variant="primary"><BookOpen className="mr-2 h-4 w-4" /> Learning rooms</Button></Link>
          <Link href="/scenarios"><Button variant="outline"><Target className="mr-2 h-4 w-4" /> Investigations</Button></Link>
        </div>
      </main>
    </div>
  );
}
