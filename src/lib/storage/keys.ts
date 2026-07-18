/**
 * Canonical registry of every browser-storage key used by the platform.
 *
 * WHY THIS EXISTS: today all state lives in `localStorage` under stringly-typed
 * keys scattered across ~15 files. Phase 1 of PRODUCTION_READINESS_PLAN.md moves
 * per-user state to a server database. Centralising the keys here gives us:
 *   1. one source of truth (no typos, no drift between reader and writer),
 *   2. a clear classification of WHICH data is per-user learner data (must move
 *      to the DB, one row per user) vs. device-local preferences vs. staff-only
 *      content-authoring state — so the migration knows exactly what to model.
 *
 * All reads/writes should go through the typed facades in this folder
 * (`progress.ts`, etc.), not by touching `localStorage` directly.
 */

/**
 * Per-user learner data. In Phase 1 each of these becomes a column/table keyed
 * by the authenticated user id (see supabase/migrations). This is the data a
 * learner expects to survive across devices and sessions.
 */
export const LEARNER_KEYS = {
  /** Global XP total (number as string). → users.total_xp */
  totalXp: "soc_total_xp",
  /** Map<roomId, RoomProgressEntry> (JSON). → room_progress table */
  roomProgress: "room_progress",
  /** DashboardSessionRecord[] (JSON). → dashboard_sessions table */
  dashboardSessions: "soc_dashboard_sessions",
  /** ScenarioRecord[] (JSON). → scenario_history table */
  scenarioHistory: "soc_scenario_history",
  /** string[] of cleared company ids (JSON). → user_progress.cleared_companies */
  clearedCompanies: "soc_company_cleared_v1",
  /** ISO date[] of used streak freezes (JSON). → user_progress.streak_freezes */
  streakFreezes: "soc_streak_freeze_dates",
  /** Bookkeeping for the last dashboard session (JSON). */
  lastSession: "soc_last_session",
} as const;

/**
 * Device-local UI preferences and one-shot flags. These are intentionally
 * device-scoped (a tour seen on a laptop needn't follow you to a phone), so in
 * Phase 1 they can stay in localStorage OR move to a lightweight per-user
 * prefs blob — low priority either way.
 */
export const PREF_KEYS = {
  selectedCompany: "soc_company",
  reportMode: "soc_report_mode_v1",
  welcomeSeen: "soc_welcome_seen_v1",
  dashboardTour: "soc-dashboard-tour-v8-done",
  logTour: "soc-log-tour-v8-done",
  recentStoryIds: "soc_recent_story_ids",
  sessionScenario: "session_scenario",
} as const;

/**
 * Staff-only content-authoring state (the Admin / Content Tools area). This is
 * NOT learner data — in Phase 2 it moves behind a staff role into a proper
 * content table, not a per-learner store. Listed here only for completeness so
 * nothing is missed during the DB migration.
 */
export const ADMIN_KEYS = {
  adminUsers: "admin_users",
  publishedScenarios: "published_scenarios",
  hiddenScenarios: "admin_hidden_scenarios",
  scenarioStatus: "admin_scenario_status",
  scenarioEdits: "admin_scenario_edits",
  hiddenLessons: "admin_hidden_lessons",
  generatedLessons: "generated_lessons",
  deletedLessonIds: "deleted_lesson_ids",
  hiddenQuizzes: "admin_hidden_quizzes",
  quizStatus: "admin_quiz_status",
  quizEdits: "admin_quiz_edits",
  generatedQuizzes: "generated_quizzes",
} as const;

export type LearnerKey = (typeof LEARNER_KEYS)[keyof typeof LEARNER_KEYS];
