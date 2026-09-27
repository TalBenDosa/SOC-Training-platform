/**
 * Pure streak logic, shared by the Topbar flame (useStreak) and the /progress
 * "Current Streak" card so both always show the same number.
 */

/** Consecutive-day streak ending today (or yesterday — the grace day). */
export function computeStreak(dates: string[], now: Date = new Date()): number {
  if (dates.length === 0) return 0;
  const daySet = new Set(dates.map(d => new Date(d).toDateString()));
  let streak = 0;
  const cursor = new Date(now);
  // Alive if the last activity was yesterday (grace period).
  if (!daySet.has(cursor.toDateString())) cursor.setDate(cursor.getDate() - 1);
  while (daySet.has(cursor.toDateString())) {
    streak += 1;
    cursor.setDate(cursor.getDate() - 1);
  }
  return streak;
}

export interface ActivitySources {
  scenarioDates?: string[];
  dashboardDates?: string[];
  /** completedAt of passed rooms. */
  roomDates?: string[];
  /** Standalone quiz completions (quiz_progress / local). */
  quizDates?: string[];
  /** Lesson completions (lesson_progress / local). */
  lessonDates?: string[];
  /** Streak-freeze days (already filtered to the allowed window). */
  freezeDates?: string[];
}

/** Every day that counts toward the streak, from every learning surface. */
export function collectActivityDates(src: ActivitySources): string[] {
  return [
    ...(src.scenarioDates ?? []),
    ...(src.dashboardDates ?? []),
    ...(src.roomDates ?? []),
    ...(src.quizDates ?? []),
    ...(src.lessonDates ?? []),
    ...(src.freezeDates ?? []),
  ].filter(d => typeof d === "string" && !Number.isNaN(new Date(d).getTime()));
}
