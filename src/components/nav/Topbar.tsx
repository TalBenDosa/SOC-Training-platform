"use client";

// Note: this Topbar intentionally has no search box, notification bell, or
// "threat level" icon. All three used to render here but did nothing when
// clicked/typed into (a decorative control that never responds trains users
// to distrust the rest of the UI's feedback) — see PLATFORM_REVIEW.md P2.2.
// Any page that genuinely needs search has its own working search field
// (e.g. the Dashboard's live event feed).
//
// The identity chip used to be hardcoded: every learner, including one who had
// registered thirty seconds earlier, was shown "Analyst / tier-2". A rank
// nobody earned is decoration, and decoration shaped like feedback is worse
// than none — it told a student they were a Tier 2 analyst before they had
// triaged a single alert. It now reflects real XP against the ladder in
// lib/progression/ranks.ts, and updates the moment XP is awarded.
import { useAuth } from "@/lib/auth/AuthContext";
import { useDisplayName } from "@/lib/auth/useDisplayName";
import { useRank } from "@/lib/progression/useRank";
import { initialFor } from "@/lib/progression/ranks";

export function Topbar({ title, subtitle, actions }: { title?: string; subtitle?: string; actions?: React.ReactNode }) {
  const { user } = useAuth();
  const { rank, next, progress, ready } = useRank();

  const displayName = useDisplayName();
  // Initial follows the displayed name, so the bubble and the label agree.
  const initial = user ? initialFor(displayName) : "A";

  // `ready` is false during SSR and the first paint, when XP is not yet
  // readable. Showing the lowest rank then would flash "Student" at a Tier 3
  // learner on every navigation, so the tier line stays blank until the real
  // value lands.
  const tierLine = ready ? rank.tier : "";

  const tooltip = ready
    ? next && progress
      ? `${rank.label} — ${rank.blurb}\n\n${progress.earned.toLocaleString()} / ${progress.needed.toLocaleString()} XP toward ${next.label} (${next.tier})`
      : `${rank.label} — ${rank.blurb}\n\nTop rank reached.`
    : undefined;

  return (
    <header className="sticky top-0 z-30 flex items-center gap-4 border-b border-border bg-bg/80 px-6 py-3 backdrop-blur">
      <div className="flex flex-1 items-center gap-4">
        {title && (
          <div>
            <h1 className="text-lg font-semibold text-white">{title}</h1>
            {subtitle && <p className="text-xs text-slate-400">{subtitle}</p>}
          </div>
        )}
        <div className="ml-auto flex items-center gap-2">
          {actions}
          <span
            className="flex items-center gap-2 rounded-md border border-border bg-bg-elevated px-2 py-1.5"
            title={tooltip}
          >
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyber-500/20 text-cyber-300 text-xs font-bold">
              {initial}
            </span>
            <span className="hidden md:flex flex-col items-start leading-tight">
              <span className="text-xs font-semibold text-slate-100">{ready ? rank.label : displayName}</span>
              <span className="text-[10px] text-slate-500 font-mono">{tierLine}</span>
            </span>
            {/* Progress toward the next rank. Omitted at max rank, where a bar
                pinned at 100% reads as a stalled loader rather than an
                achievement. */}
            {ready && progress && (
              <span className="hidden lg:block h-1 w-16 overflow-hidden rounded-full bg-slate-700/60" aria-hidden>
                <span
                  className="block h-full rounded-full bg-cyber-400 transition-[width] duration-500"
                  style={{ width: `${progress.pct}%` }}
                />
              </span>
            )}
          </span>
        </div>
      </div>
    </header>
  );
}
