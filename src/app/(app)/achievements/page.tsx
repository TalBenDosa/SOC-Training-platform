"use client";
/**
 * Achievements — the learner's certificate shelf.
 *
 * Rank-up certificates are normally seen once, at the moment of promotion. This
 * page lets a learner come back and re-download any certificate they have
 * ALREADY earned — and shows the ranks still ahead as locked, with the XP left
 * to reach them, so the shelf doubles as a goal board. It never shows a
 * certificate for a rank that hasn't been reached: locked cards render a
 * placeholder, not the real artefact.
 */
import { useEffect, useRef, useState } from "react";
import { Topbar } from "@/components/nav/Topbar";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { RANKS, rankForXp, type Rank } from "@/lib/progression/ranks";
import { certMetaForRank, drawCertificate } from "@/lib/certificate/renderCertificate";
import { RankCertificateModal } from "@/components/certificate/RankCertificateModal";
import { useFullName } from "@/lib/auth/useFullName";
import { getTotalXp } from "@/lib/storage/progress";
import { format } from "date-fns";
import { Lock, Award, Download, Sparkles } from "lucide-react";

// The certifiable ranks — everything above the entry "Student" rank. You are
// never promoted INTO Student, so it never earns a certificate.
const CERT_RANKS = RANKS.filter(r => r.id !== "student");

function commas(n: number) {
  return n.toLocaleString("en-US");
}

/** A live mini-render of a rank's certificate, drawn into a downscaled canvas. */
function CertThumb({ rank, name }: { rank: Rank; name: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    let cancelled = false;
    drawCertificate(
      canvas,
      { meta: certMetaForRank(rank), name, xp: rank.minXp, date: format(new Date(), "d MMM yyyy") },
      1,
    ).catch(() => {});
    return () => { cancelled = true; void cancelled; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rank.id, name]);
  return <canvas ref={ref} className="block h-auto w-full" aria-hidden />;
}

export default function AchievementsPage() {
  usePageTitle("Achievements");
  const name = useFullName();
  const [totalXp, setTotalXp] = useState(0);
  const [selected, setSelected] = useState<Rank | null>(null);

  // Read on mount, then keep it live: XP is written from several places and a
  // remote backend can hydrate just after mount, so poll the one integer like
  // EarnMoment does rather than risk showing a stale "locked" card.
  useEffect(() => {
    setTotalXp(getTotalXp());
    const id = setInterval(() => setTotalXp(getTotalXp()), 1500);
    return () => clearInterval(id);
  }, []);

  const currentRank = rankForXp(totalXp);
  const earnedCount = CERT_RANKS.filter(r => totalXp >= r.minXp).length;

  return (
    <div>
      <Topbar
        title="Achievements"
        subtitle="Every rank you earn issues a shareable certificate. Re-download yours here."
      />

      <div className="container mx-auto max-w-[1100px] px-6 py-6 space-y-6">
        {/* Summary strip */}
        <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-border bg-bg-elevated px-6 py-5">
          <div className="flex items-center gap-3">
            <span className="flex h-11 w-11 items-center justify-center rounded-lg border border-neon-amber/40 bg-neon-amber/10">
              <Award className="h-6 w-6 text-neon-amber" />
            </span>
            <div>
              <p className="text-lg font-bold text-white">
                {earnedCount} of {CERT_RANKS.length} certificates earned
              </p>
              <p className="text-xs text-slate-400">
                Current rank: <span className="text-cyber-300 font-semibold">{currentRank.label}</span> · {commas(totalXp)} XP
              </p>
            </div>
          </div>
          {earnedCount < CERT_RANKS.length && (
            <p className="flex items-center gap-1.5 text-xs text-slate-400">
              <Sparkles className="h-3.5 w-3.5 text-cyber-300" />
              Keep training to unlock the next one.
            </p>
          )}
        </div>

        {/* Certificate grid */}
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          {CERT_RANKS.map(rank => {
            const earned = totalXp >= rank.minXp;
            const meta = certMetaForRank(rank);
            const remaining = rank.minXp - totalXp;

            if (earned) {
              return (
                <button
                  key={rank.id}
                  onClick={() => setSelected(rank)}
                  className="group text-left rounded-xl border border-border/70 bg-bg-elevated overflow-hidden transition hover:border-cyber-500/50 hover:shadow-[0_0_30px_-14px_rgba(6,182,212,0.5)] focus:outline-none focus-visible:ring-2 focus-visible:ring-cyber-500/50"
                  aria-label={`View and download your ${meta.title} ${meta.tier} certificate`}
                >
                  <div className="relative">
                    <CertThumb rank={rank} name={name} />
                    <div className="absolute inset-0 flex items-center justify-center bg-black/0 opacity-0 transition group-hover:bg-black/40 group-hover:opacity-100">
                      <span className="flex items-center gap-2 rounded-lg bg-cyber-500/90 px-3.5 py-2 text-xs font-bold text-[#05070d]">
                        <Download className="h-4 w-4" /> View &amp; download
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center justify-between px-4 py-3">
                    <div>
                      <p className="text-sm font-bold text-white">{meta.title}</p>
                      <p className="text-[11px] uppercase tracking-wider" style={{ color: meta.accent }}>{meta.tier}</p>
                    </div>
                    <span className="rounded-full border border-neon-green/30 bg-neon-green/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-neon-green">
                      Earned
                    </span>
                  </div>
                </button>
              );
            }

            // Locked — placeholder, never the real certificate.
            return (
              <div
                key={rank.id}
                className="rounded-xl border border-border/40 bg-[#0a0f18] overflow-hidden opacity-90"
                aria-label={`${meta.title} ${meta.tier} certificate — locked`}
              >
                <div className="relative flex aspect-[1200/630] items-center justify-center bg-gradient-to-br from-[#0b1220] to-[#050810]">
                  <div className="flex flex-col items-center gap-2 text-center px-4">
                    <span
                      className="flex h-16 w-16 items-center justify-center rounded-full border-2"
                      style={{ borderColor: "rgba(148,163,184,.3)" }}
                    >
                      <Lock className="h-6 w-6 text-slate-500" />
                    </span>
                    <p className="text-sm font-bold text-slate-300">{meta.title}</p>
                    <p className="text-[11px] uppercase tracking-wider text-slate-500">{meta.tier}</p>
                    <p className="mt-1 text-xs text-cyber-300">
                      {commas(Math.max(0, remaining))} XP to unlock
                    </p>
                  </div>
                </div>
                <div className="flex items-center justify-between px-4 py-3">
                  <p className="text-sm font-bold text-slate-400">{meta.title}</p>
                  <span className="flex items-center gap-1 rounded-full border border-slate-700 bg-slate-800/60 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-slate-400">
                    <Lock className="h-2.5 w-2.5" /> Locked
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        <p className="text-center text-[11px] text-slate-500">
          Certificates carry your name and rank only — never your account or email.
        </p>
      </div>

      {selected && (
        <RankCertificateModal
          rank={selected}
          xp={selected.minXp}
          name={name}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}
