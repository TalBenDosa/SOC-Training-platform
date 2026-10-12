"use client";
/**
 * "Where is the learner right now" — published by the screen they are on, read by the
 * global "Report a problem" button, so a report says which lesson page, room task, quiz
 * question, scenario or live-feed log it is about without the learner having to describe it.
 *
 * A tiny module-level store (useSyncExternalStore), not a React context: the button lives
 * in the app layout, the screens publishing a location are deep below it, and a screen
 * must clear its location when it unmounts so a report never points at a page already left.
 */
import { useEffect, useSyncExternalStore } from "react";

export type ReportKind = "lesson" | "room_task" | "quiz" | "scenario" | "dashboard";

export interface ReportLocation {
  kind: ReportKind;
  /** Stable id the server resolves: lessonKey, roomId:taskId, quizSlug:questionId, scenario slug, event id. */
  targetId: string;
  /** Human breadcrumb, e.g. "SOC Analyst › Windows Event Logs". */
  where: string;
  /** Position inside it, e.g. "Page 3 of 9" or "Task 5 of 16". */
  step?: string;
  /** What is on screen: the page title, the question, the log line. */
  shown?: string;
}

let current: ReportLocation | null = null;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach(l => l());

export function setReportLocation(loc: ReportLocation | null): void {
  current = loc;
  emit();
}

function subscribe(l: () => void) { listeners.add(l); return () => { listeners.delete(l); }; }
const snapshot = () => current;
const serverSnapshot = () => null;

/** The location the current screen published, or null. */
export function useReportLocation(): ReportLocation | null {
  return useSyncExternalStore(subscribe, snapshot, serverSnapshot);
}

/**
 * Publish this screen's location while it is mounted. Pass null while there is nothing
 * specific to point at (still loading). The key fields are compared, not the object, so an
 * inline literal does not republish on every render.
 */
export function usePublishReportLocation(loc: ReportLocation | null): void {
  const key = loc ? `${loc.kind}|${loc.targetId}|${loc.where}|${loc.step ?? ""}|${loc.shown ?? ""}` : "";
  useEffect(() => {
    setReportLocation(loc);
    return () => { if (current && loc && current.targetId === loc.targetId && current.kind === loc.kind) setReportLocation(null); };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- keyed on the location's content, not its identity
  }, [key]);
}
