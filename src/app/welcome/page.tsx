"use client";
/**
 * The entry screen shown once, immediately after signing in.
 *
 * NOT a navigation destination — it is deliberately absent from the sidebar.
 * A learner passes through it on the way into the platform; they do not come
 * back to it. Everything it shows (score, badge) lives in the Topbar and on
 * /progress for the rest of the session, so repeating it as a nav item would
 * be a third copy of the same numbers.
 *
 * One greeting, the two facts that orient you, one way forward.
 */
import Link from "next/link";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth/AuthContext";
import { useRank } from "@/lib/progression/useRank";
import { ArrowRight } from "lucide-react";

export default function WelcomePage() {
  const { user } = useAuth();
  const { xp, rank, ready } = useRank();

  // The closest thing to a name we hold without asking for one.
  const name = user?.email?.split("@")[0] ?? "analyst";

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden px-6 py-16">
      {/* Background, matching the landing page's treatment */}
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[600px] bg-cyber-grid" />
      <div className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-[600px] bg-cyber-glow" />

      <div className="w-full max-w-xl text-center">

        <p className="text-lg text-slate-300">
          Hello <span className="font-semibold text-white">{name}</span>
        </p>
        <h1 className="mt-2 text-3xl font-bold text-white sm:text-4xl">
          Welcome to <span className="text-cyber-300">Hack The SOC</span>
        </h1>

        {/* ── Score + badge ──────────────────────────────────────────── */}
        <Card className={cn(
          "mt-10 p-8 ring-1 transition-shadow",
          ready ? `${rank.accent.ring} shadow-lg ${rank.accent.glow}` : "ring-border",
        )}>
          <div className="flex flex-col items-center gap-6 sm:flex-row sm:justify-center sm:gap-12">

            <div>
              <p className="text-xs uppercase tracking-widest text-slate-500">Score</p>
              <p className="mt-1 font-mono text-4xl font-bold text-white">
                {ready ? xp.toLocaleString() : "–"}
                <span className="ml-1.5 text-base font-normal text-slate-500">XP</span>
              </p>
            </div>

            <div className="hidden h-16 w-px bg-border sm:block" />

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

        {/* ── The one way forward ────────────────────────────────────── */}
        <div className="mt-10">
          <Link href="/rooms">
            <Button variant="primary" size="lg">
              Start Training <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}
