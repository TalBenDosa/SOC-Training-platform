"use client";
import { useCallback, useEffect, useRef } from "react";

/**
 * Per-task behavioral telemetry — Phase 1 (see ANALYST_TELEMETRY_PLAN.md).
 * Pure client-side timestamp math: how long a task was on screen before the
 * first click, and before the final answer, plus a raw interaction count.
 * This is a secondary signal alongside correctness — never a substitute for
 * it (a fast wrong answer must never look better than a slow correct one).
 */
export interface TaskTelemetryEntry {
  taskId: string;
  shownAt: number;
  firstInteractionAt: number | null;
  submittedAt: number;
  decisionLatencyMs: number;       // submittedAt - shownAt
  interactionCount: number;        // raw click/change events before submit — not a "changed answer" signal, just activity volume
}

/**
 * Tracks timing for whichever task is currently mounted. Callers remount
 * this (or pass a new taskId) per task — e.g. RoomClient already keys
 * TaskPlayer by task.id, which resets this hook's refs naturally.
 */
export function useTaskTelemetry(taskId: string) {
  const shownAtRef = useRef(Date.now());
  const firstInteractionRef = useRef<number | null>(null);
  const interactionCountRef = useRef(0);

  useEffect(() => {
    shownAtRef.current = Date.now();
    firstInteractionRef.current = null;
    interactionCountRef.current = 0;
  }, [taskId]);

  const recordInteraction = useCallback(() => {
    if (firstInteractionRef.current === null) firstInteractionRef.current = Date.now();
    interactionCountRef.current += 1;
  }, []);

  const finalize = useCallback((): TaskTelemetryEntry => {
    const submittedAt = Date.now();
    return {
      taskId,
      shownAt: shownAtRef.current,
      firstInteractionAt: firstInteractionRef.current,
      submittedAt,
      decisionLatencyMs: submittedAt - shownAtRef.current,
      interactionCount: interactionCountRef.current,
    };
  }, [taskId]);

  return { recordInteraction, finalize };
}
