/**
 * Typed learner-progress facade. ALL per-user reads/writes go through here so
 * that Phase 1 (server DB) is a backend swap in `backend.ts` with zero call-site
 * changes. See keys.ts for the key registry and the DB-column mapping.
 */
import { backend, readJson, writeJson } from "./backend";
import { LEARNER_KEYS } from "./keys";
import type { DashboardSessionRecord } from "@/app/(app)/dashboard/useLiveEvents";

// Structural shapes re-declared here to avoid importing heavy client modules for
// types. They mirror the canonical definitions (RoomClient.tsx, ScenarioClient.tsx);
// keep in sync if those change.
export interface RoomProgressEntry {
  completedTaskIds: string[];
  xpEarned: number;
  completedAt?: string;
  perTaskXp?: Record<string, number>;
  telemetry?: unknown[];
}
export type RoomProgressMap = Record<string, RoomProgressEntry>;

export interface ScenarioRecord {
  slug: string;
  title: string;
  score: number;
  xpEarned: number;
  timeTaken: number;
  date: string;
}

// ─── XP ──────────────────────────────────────────────────────────────────────
export function getTotalXp(): number {
  return parseInt(backend.get(LEARNER_KEYS.totalXp) ?? "0", 10) || 0;
}
export function setTotalXp(xp: number): void {
  backend.set(LEARNER_KEYS.totalXp, String(Math.max(0, Math.round(xp))));
}
/** Add (or subtract, floored at 0) XP to the running total. Returns the new total. */
export function addTotalXp(delta: number): number {
  const next = Math.max(0, getTotalXp() + delta);
  backend.set(LEARNER_KEYS.totalXp, String(next));
  return next;
}

// ─── Room progress ─────────────────────────────────────────────────────────────
export function getRoomProgress(): RoomProgressMap {
  return readJson<RoomProgressMap>(LEARNER_KEYS.roomProgress, {});
}
export function saveRoomProgress(map: RoomProgressMap): void {
  writeJson(LEARNER_KEYS.roomProgress, map);
}

// ─── Dashboard sessions ──────────────────────────────────────────────────────────
export function getDashboardSessions(): DashboardSessionRecord[] {
  return readJson<DashboardSessionRecord[]>(LEARNER_KEYS.dashboardSessions, []);
}
/** Append a session record, keeping the most recent `cap` (default 50). */
export function appendDashboardSession(record: DashboardSessionRecord, cap = 50): void {
  writeJson(LEARNER_KEYS.dashboardSessions, [...getDashboardSessions(), record].slice(-cap));
}

// ─── Scenario history ────────────────────────────────────────────────────────────
export function getScenarioHistory(): ScenarioRecord[] {
  return readJson<ScenarioRecord[]>(LEARNER_KEYS.scenarioHistory, []);
}
export function appendScenarioRecord(record: ScenarioRecord): void {
  writeJson(LEARNER_KEYS.scenarioHistory, [...getScenarioHistory(), record]);
}

// ─── Cleared companies ───────────────────────────────────────────────────────────
export function getClearedCompanies(): string[] {
  return readJson<string[]>(LEARNER_KEYS.clearedCompanies, []);
}
export function addClearedCompany(id: string): void {
  const set = new Set(getClearedCompanies());
  set.add(id);
  writeJson(LEARNER_KEYS.clearedCompanies, Array.from(set));
}

// ─── Streak freezes ──────────────────────────────────────────────────────────────
export function getStreakFreezeDates(): string[] {
  return readJson<string[]>(LEARNER_KEYS.streakFreezes, []);
}
export function saveStreakFreezeDates(dates: string[]): void {
  writeJson(LEARNER_KEYS.streakFreezes, dates);
}
