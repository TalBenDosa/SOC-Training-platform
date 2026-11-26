/** Sign-in, presence and activity of one learner, for the student page and the progress report. */

export interface ActivityDay {
  /** UTC day, YYYY-MM-DD. */
  date: string;
  /** The learner was on the platform that day (presence beat) or left a dated learning record. */
  active: boolean;
  /** Active minutes that day from presence beats; null when presence was not recorded that day. */
  minutes: number | null;
  /** Graded answers given that day. */
  answers: number;
}

export interface StudentActivity {
  /** Last PASSWORD sign-in (Supabase auth): the start of the learner's current session. A learner
   *  who stays signed in keeps one session for weeks, so this is NOT when they were last here. */
  last_sign_in_at: string | null;
  /** Last time the signed-in session was renewed (migration 0123), null if unknown. */
  last_session_at?: string | null;
  /** When the learner was really last on the platform: the latest of the sign-in, the session
   *  renewal, the presence beats and every dated learning record. */
  last_seen_at?: string | null;
  /** Days (UTC) with any learning activity in this org: answers, rooms, scenarios, live shifts. */
  active_days_7: number;
  active_days_30: number;
  /** Graded answers given in the last 7 / 30 days. */
  answered_7: number;
  answered_30: number;
  /** Active days per week for the last 4 weeks, oldest first. */
  weeks: number[];
  /** Visits (a return after 30 minutes away counts as a new one) and active minutes in the last
   *  30 days, from presence beats; null until presence is recorded for this learner. */
  visits_30?: number | null;
  active_minutes_30?: number | null;
  /** The last 30 days, oldest first. */
  days?: ActivityDay[];
}

/** One day of presence beats (user_presence_days, migration 0123). */
export interface PresenceDay {
  day: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  active_seconds: number;
  visits: number;
}

export interface SeenSources {
  last_sign_in_at?: string | null;
  last_session_at?: string | null;
  presence?: PresenceDay[];
}

const DAY = 86_400_000;

/** The latest valid date of a list, as ISO, or null. Dates in the future are ignored. */
export function latestOf(dates: (string | null | undefined)[], now = Date.now()): string | null {
  let best: number | null = null;
  for (const d of dates) {
    if (!d) continue;
    const t = Date.parse(d);
    // A minute of tolerance for clock skew between the database and the server.
    if (!Number.isNaN(t) && t <= now + 60_000 && (best === null || t > best)) best = t;
  }
  return best === null ? null : new Date(best).toISOString();
}

/**
 * When a learner was really last on the platform. The last sign-in alone is wrong for anyone who
 * stays signed in (it is the day they last typed a password), so every signal counts.
 */
export function lastSeenOf(seen: SeenSources | null | undefined, activityDates: (string | null | undefined)[], now = Date.now()): string | null {
  return latestOf([
    seen?.last_sign_in_at, seen?.last_session_at,
    ...(seen?.presence ?? []).map(p => p.last_seen_at),
    ...activityDates,
  ], now);
}

/** Active days, answer counts, presence totals and the 30-day strip. Pure. */
export function activityOf(
  dates: (string | null | undefined)[],
  answerDates: (string | null | undefined)[],
  lastSignIn: string | null,
  now = Date.now(),
  seen?: SeenSources | null,
): StudentActivity {
  const presence = seen?.presence ?? [];
  const today = Math.floor(now / DAY);
  const dayOf = (iso: string | null | undefined) => { const t = Date.parse(iso ?? ""); return Number.isNaN(t) || t > now + 60_000 ? null : Math.floor(t / DAY); };

  const days = new Set<number>();
  for (const d of dates) { const n = dayOf(d); if (n !== null) days.add(n); }
  const presenceBy = new Map<number, PresenceDay>();
  for (const p of presence) { const n = dayOf(`${p.day}T00:00:00Z`); if (n !== null) { presenceBy.set(n, p); days.add(n); } }
  const answersBy = new Map<number, number>();
  const answers: number[] = [];
  for (const d of answerDates) {
    const t = Date.parse(d ?? "");
    if (Number.isNaN(t)) continue;
    answers.push(t);
    const n = Math.floor(t / DAY);
    answersBy.set(n, (answersBy.get(n) ?? 0) + 1);
  }

  const within = (n: number) => [...days].filter(d => today - d >= 0 && today - d < n).length;
  const recent = presence.filter(p => { const n = dayOf(`${p.day}T00:00:00Z`); return n !== null && today - n < 30; });
  const strip: ActivityDay[] = [];
  for (let back = 29; back >= 0; back--) {
    const n = today - back;
    const p = presenceBy.get(n);
    strip.push({
      date: new Date(n * DAY).toISOString().slice(0, 10),
      active: days.has(n),
      minutes: p ? Math.round(p.active_seconds / 60) : null,
      answers: answersBy.get(n) ?? 0,
    });
  }

  return {
    last_sign_in_at: lastSignIn,
    last_session_at: seen?.last_session_at ?? null,
    last_seen_at: lastSeenOf({ ...seen, last_sign_in_at: lastSignIn }, [...dates, ...answerDates], now),
    active_days_7: within(7),
    active_days_30: within(30),
    answered_7: answers.filter(t => now - t < 7 * DAY).length,
    answered_30: answers.filter(t => now - t < 30 * DAY).length,
    weeks: [3, 2, 1, 0].map(w => [...days].filter(d => today - d >= w * 7 && today - d < (w + 1) * 7).length),
    visits_30: presence.length ? recent.reduce((n, p) => n + p.visits, 0) : null,
    active_minutes_30: presence.length ? Math.round(recent.reduce((n, p) => n + p.active_seconds, 0) / 60) : null,
    days: strip,
  };
}
