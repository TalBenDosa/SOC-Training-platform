/**
 * Learner rank ladder.
 *
 * The Topbar used to render a hardcoded "Analyst / tier-2" for everybody,
 * including someone who had just registered. A rank that is not earned is
 * decoration, and decoration that looks like feedback is worse than none —
 * it tells a student they are a Tier 2 analyst before they have triaged
 * anything.
 *
 * The ladder mirrors a real SOC career path, because the names themselves are
 * part of what the platform teaches: a student should leave knowing what Tier 1
 * versus Tier 3 actually means as a job, not just as a score.
 *
 * CALIBRATION. The whole corpus is worth roughly 33,800 XP today:
 *
 *     rooms      21,455      lessons     4,070
 *     scenarios   6,715      quizzes    ~1,600
 *
 * Tier 3 sits at 22,000 — about 65% of everything available. That is
 * deliberate. Requiring ~100% would make the top rank a completion trophy for
 * grinding rather than a competence marker, and would also mean the ceiling
 * moves every time content is added. At 65% a learner reaches the top by
 * covering the material properly while still leaving room to keep going.
 *
 * The thresholds are also front-loaded: the first promotion arrives at 1,500,
 * which is roughly four or five rooms. Early feedback matters far more than
 * late feedback for someone deciding whether to continue.
 *
 * When adding content, re-check these numbers against the real total —
 * `scripts/audit-scenarios.mjs` and the content gate both print corpus sizes.
 */

export interface Rank {
  /** Stable id — safe to persist or compare against. */
  id: string;
  /** Short label shown in the Topbar. */
  label: string;
  /** The tier line under the label. Empty for pre-tier ranks. */
  tier: string;
  /** XP at which this rank is reached. */
  minXp: number;
  /** What this rank means as an actual job. Shown as a tooltip / on the profile. */
  blurb: string;
}

export const RANKS: Rank[] = [
  {
    id: "student",
    label: "Student",
    tier: "learning",
    minXp: 0,
    blurb: "Just started. Working through the foundations — how logs, networks and identities actually work.",
  },
  {
    id: "trainee",
    label: "SOC Trainee",
    tier: "trainee",
    minXp: 1_500,
    blurb: "Can read a log line and say what it records. Learning to tell normal from noteworthy.",
  },
  {
    id: "tier-1",
    label: "Analyst",
    tier: "tier-1",
    minXp: 5_000,
    blurb: "Tier 1 — triage. Works the alert queue, separates false positives from real findings, and escalates with evidence.",
  },
  {
    id: "tier-2",
    label: "Analyst",
    tier: "tier-2",
    minXp: 12_000,
    blurb: "Tier 2 — investigation. Reconstructs an intrusion across log sources, scopes it, and writes the incident report.",
  },
  {
    id: "tier-3",
    label: "Senior Analyst",
    tier: "tier-3",
    minXp: 22_000,
    blurb: "Tier 3 — threat hunting and incident lead. Hunts without an alert to start from, and decides containment.",
  },
];

/** The rank a learner currently holds. Never returns undefined — 0 XP is Student. */
export function rankForXp(xp: number): Rank {
  const safe = Number.isFinite(xp) ? Math.max(0, xp) : 0;
  // Walk down so the HIGHEST satisfied threshold wins.
  for (let i = RANKS.length - 1; i >= 0; i--) {
    if (safe >= RANKS[i].minXp) return RANKS[i];
  }
  return RANKS[0];
}

/** The next rank up, or null at the top of the ladder. */
export function nextRank(xp: number): Rank | null {
  const current = rankForXp(xp);
  const i = RANKS.findIndex(r => r.id === current.id);
  return RANKS[i + 1] ?? null;
}

/**
 * Progress toward the next rank, for a progress bar.
 * Returns null at max rank — callers should show "max rank reached" rather
 * than a bar stuck at 100%, which reads as a stalled load.
 */
export function rankProgress(xp: number): { earned: number; needed: number; pct: number } | null {
  const safe = Number.isFinite(xp) ? Math.max(0, xp) : 0;
  const current = rankForXp(safe);
  const next = nextRank(safe);
  if (!next) return null;
  const earned = safe - current.minXp;
  const needed = next.minXp - current.minXp;
  // FLOOR, not round. With rounding, 1,499 of 1,500 XP displays as a full bar
  // while the learner has not actually been promoted — the one moment where a
  // wrong pixel is read as "I finished this and nothing happened". Flooring
  // means the bar only fills when the rank actually changes.
  return { earned, needed, pct: Math.min(99, Math.floor((earned / needed) * 100)) };
}

/** Initial for the avatar bubble. Falls back to "A" for anonymous/local mode. */
export function initialFor(nameOrEmail: string | null | undefined): string {
  const s = (nameOrEmail ?? "").trim();
  if (!s) return "A";
  return s[0].toUpperCase();
}
