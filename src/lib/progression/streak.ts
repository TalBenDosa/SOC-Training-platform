/**
 * Daily-activity streak, shared between /home and /progress.
 *
 * Extracted from the Progress page rather than reimplemented, because two
 * screens computing the same number independently is how they end up
 * disagreeing — and a streak the learner sees as 6 in one place and 5 in
 * another destroys trust in every other number on the page.
 */

/**
 * Consecutive days of activity, ending today or yesterday.
 *
 * Yesterday still counts as alive: a learner who has not opened the app YET
 * today has not broken anything, and telling them their streak is zero at
 * 09:00 would be both wrong and discouraging.
 */
export function computeStreak(dates: string[]): number {
  if (dates.length === 0) return 0;
  const daySet = new Set(dates.map(d => new Date(d).toDateString()));
  let streak = 0;
  const cursor = new Date();
  if (!daySet.has(cursor.toDateString())) cursor.setDate(cursor.getDate() - 1);
  while (daySet.has(cursor.toDateString())) {
    streak += 1;
    cursor.setDate(cursor.getDate() - 1);
  }
  return streak;
}

/** True when there is a live streak that today's inactivity would end. */
export function streakAtRisk(dates: string[]): boolean {
  if (computeStreak(dates) === 0) return false;
  const daySet = new Set(dates.map(d => new Date(d).toDateString()));
  return !daySet.has(new Date().toDateString());
}
