/** Sign-in and activity of one learner, for the progress report (GET /api/org/students/[id]). */

export interface StudentActivity {
  /** Last sign-in to the platform (Supabase auth), null if never or unknown. */
  last_sign_in_at: string | null;
  /** Days (UTC) with any learning activity in this org: answers, rooms, scenarios, live shifts. */
  active_days_7: number;
  active_days_30: number;
  /** Graded answers given in the last 7 / 30 days. */
  answered_7: number;
  answered_30: number;
  /** Active days per week for the last 4 weeks, oldest first. */
  weeks: number[];
}

/** Active days and answer counts from every dated activity row. Pure. */
export function activityOf(dates: (string | null | undefined)[], answerDates: (string | null | undefined)[], lastSignIn: string | null, now = Date.now()): StudentActivity {
  const DAY = 86_400_000;
  const days = new Set<number>();
  for (const d of dates) { const t = Date.parse(d ?? ""); if (!Number.isNaN(t) && t <= now) days.add(Math.floor(t / DAY)); }
  const today = Math.floor(now / DAY);
  const within = (n: number) => [...days].filter(d => today - d < n).length;
  const answers = answerDates.map(d => Date.parse(d ?? "")).filter(t => !Number.isNaN(t));
  return {
    last_sign_in_at: lastSignIn,
    active_days_7: within(7),
    active_days_30: within(30),
    answered_7: answers.filter(t => now - t < 7 * DAY).length,
    answered_30: answers.filter(t => now - t < 30 * DAY).length,
    weeks: [3, 2, 1, 0].map(w => [...days].filter(d => today - d >= w * 7 && today - d < (w + 1) * 7).length),
  };
}
