"use client";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Trophy, Star } from "lucide-react";
import { rankForXp, type Rank } from "@/lib/progression/ranks";
import { getTotalXp } from "@/lib/storage/progress";
import { useRank } from "@/lib/progression/useRank";
import { useFullName } from "@/lib/auth/useFullName";
import { RankCertificateModal } from "@/components/certificate/RankCertificateModal";

/**
 * The "earn moment": nothing ever celebrated crossing a rank threshold — the
 * single cheapest motivation win. This global component watches soc_total_xp
 * and fires a celebration toast on a rank promotion, wherever the XP was earned
 * (rooms, dashboard, scenarios).
 *
 * Uses the CANONICAL rank ladder (lib/progression/ranks.ts) — the same one the
 * Topbar and the /progress ladder use — so a "Rank Up!" toast can never announce
 * a different rank than the rest of the UI shows. (It previously used an old,
 * separate xp/1000 level system in lib/utils.ts, which contradicted the Topbar.)
 *
 * It polls the total XP via the storage facade (getTotalXp) because XP is
 * written from several places and same-tab writes don't emit a `storage` event.
 * Polling one integer every ~1.5s is negligible and catches every source
 * (guest localStorage or signed-in DB) without touching them.
 */
type Celebration = { title: string; sub: string };

/** localStorage key holding the minXp of the highest rank already celebrated on
 *  this device, so a promotion pops exactly once — never again on reload/login. */
const ACK_KEY = "soc_ack_rank_minxp";

/** "Analyst · Tier 1", "Senior Analyst · Tier 3", "SOC Trainee", "Student". */
function rankLabel(r: Rank): string {
  return r.tier.startsWith("tier-") ? `${r.label} · ${r.tier.replace("tier-", "Tier ")}` : r.label;
}

export function EarnMoment() {
  const [mounted, setMounted] = useState(false);
  const [celebration, setCelebration] = useState<Celebration | null>(null);
  // The promotion that should raise a certificate. Held separately from the
  // toast so the two lifetimes are independent: the toast auto-hides, the
  // certificate modal stays until dismissed.
  const [certRank, setCertRank] = useState<{ rank: Rank; xp: number } | null>(null);
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const name = useFullName();
  // Reactive, DB-or-localStorage backed; `ready` is false until the REAL xp has
  // loaded — which is what stops the old bug where the 0→real jump on every page
  // load looked like a promotion and re-popped the certificate.
  const { xp, rank, ready } = useRank();

  useEffect(() => { setMounted(true); }, []);

  useEffect(() => {
    if (!ready) return;
    let acked: number | null = null;
    try { const v = localStorage.getItem(ACK_KEY); if (v !== null) { const n = parseInt(v, 10); acked = Number.isNaN(n) ? null : n; } } catch { /* ignore */ }

    // First time on this device: baseline AFTER a short settle so we capture the
    // REAL loaded rank, not the transient 0 that getTotalXp() returns before the
    // signed-in XP syncs. No certificate — this is not a promotion.
    if (acked === null) {
      const t = setTimeout(() => {
        try { localStorage.setItem(ACK_KEY, String(rankForXp(getTotalXp()).minXp)); } catch { /* ignore */ }
      }, 4000);
      return () => clearTimeout(t);
    }

    // acked is MONOTONIC — only ever raised, never lowered. So the transient
    // 0-XP load (rank.minXp < acked) is ignored, and a reload (rank.minXp ===
    // acked) shows nothing. A certificate fires only on a genuine NEW high,
    // once, then acked catches up so it can't fire again.
    if (rank.minXp > acked) {
      show({ title: "Rank Up!", sub: rankLabel(rank) });
      if (rank.id !== "student") setCertRank({ rank, xp });
      try { localStorage.setItem(ACK_KEY, String(rank.minXp)); } catch { /* ignore */ }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready, rank.id, rank.minXp, xp]);

  useEffect(() => () => { if (hideTimer.current) clearTimeout(hideTimer.current); }, []);

  function show(c: Celebration) {
    setCelebration(c);
    if (hideTimer.current) clearTimeout(hideTimer.current);
    hideTimer.current = setTimeout(() => setCelebration(null), 4200);
  }

  if (!mounted) return null;

  return (
    <>
      {certRank && (
        <RankCertificateModal
          rank={certRank.rank}
          xp={certRank.xp}
          name={name}
          onClose={() => setCertRank(null)}
        />
      )}
      {createPortal(
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
              <Trophy className="h-5 w-5 text-neon-amber" />
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
      )}
    </>
  );
}
