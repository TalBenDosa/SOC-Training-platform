"use client";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Trophy, Zap, Star } from "lucide-react";
import { levelFromXp, rankFromXp } from "@/lib/utils";
import { getTotalXp } from "@/lib/storage/progress";

/**
 * The "earn moment" (UX_FINDINGS.md, fix #4). XP/level/rank are all computed
 * from soc_total_xp but nothing ever celebrated crossing a threshold — the
 * single cheapest motivation win. This global component watches soc_total_xp
 * and fires a celebration toast on a level-up or rank promotion, wherever the
 * XP was earned (rooms, dashboard, scenarios).
 *
 * It polls localStorage because XP is written with plain setItem from several
 * places and same-tab writes don't emit a `storage` event. Polling one integer
 * every ~1.5s is negligible and catches every source without touching them.
 */
type Celebration = { kind: "rank" | "level"; title: string; sub: string };

const readXp = getTotalXp;

export function EarnMoment() {
  const [mounted, setMounted] = useState(false);
  const [celebration, setCelebration] = useState<Celebration | null>(null);
  const lastLevel = useRef<number | null>(null);
  const lastRank = useRef<string | null>(null);
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setMounted(true);
    // Baseline from current XP so we never fire on first load.
    const xp = readXp();
    lastLevel.current = levelFromXp(xp);
    lastRank.current = rankFromXp(xp);

    const id = setInterval(() => {
      const xp = readXp();
      const level = levelFromXp(xp);
      const rank = rankFromXp(xp);
      const prevLevel = lastLevel.current ?? level;
      const prevRank = lastRank.current ?? rank;

      // Rank promotion is the bigger deal — prefer it when both happen.
      if (rank !== prevRank && level >= prevLevel && prevRank !== null) {
        show({ kind: "rank", title: "Rank Up!", sub: rank });
      } else if (level > prevLevel) {
        show({ kind: "level", title: "Level Up!", sub: `Level ${level}` });
      }

      lastLevel.current = level;
      lastRank.current = rank;
    }, 1500);

    return () => {
      clearInterval(id);
      if (hideTimer.current) clearTimeout(hideTimer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function show(c: Celebration) {
    setCelebration(c);
    if (hideTimer.current) clearTimeout(hideTimer.current);
    hideTimer.current = setTimeout(() => setCelebration(null), 4200);
  }

  if (!mounted) return null;

  return createPortal(
    <AnimatePresence>
      {celebration && (
        <motion.div
          key={celebration.title + celebration.sub}
          initial={{ opacity: 0, y: -24, scale: 0.9 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -16, scale: 0.95 }}
          transition={{ type: "spring", damping: 18, stiffness: 260 }}
          className="fixed top-6 left-1/2 z-[100] -translate-x-1/2 cursor-pointer"
          onClick={() => setCelebration(null)}
          role="status"
          aria-live="polite"
        >
          <div className="flex items-center gap-3 rounded-2xl border border-neon-amber/50 bg-[#0d1520] px-5 py-3 shadow-[0_0_40px_0_rgba(255,193,7,0.25)]">
            <div className="flex h-10 w-10 items-center justify-center rounded-full border-2 border-neon-amber/60 bg-neon-amber/15">
              {celebration.kind === "rank"
                ? <Trophy className="h-5 w-5 text-neon-amber" />
                : <Zap className="h-5 w-5 text-neon-amber" />}
            </div>
            <div>
              <p className="flex items-center gap-1.5 text-sm font-black uppercase tracking-wider text-neon-amber">
                <Star className="h-3.5 w-3.5" /> {celebration.title}
              </p>
              <p className="text-base font-bold text-white">{celebration.sub}</p>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body
  );
}
