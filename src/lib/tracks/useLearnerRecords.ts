"use client";
/**
 * The learner's records that recommended-track progress is derived from, read through
 * the storage facade once the signed-in learner's progress has hydrated (before
 * that the cache holds this browser's guest data, which must not show as theirs).
 */
import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth/AuthContext";
import { useProgressSnapshot } from "@/lib/storage/useProgressSnapshot";
import {
  getRoomProgress, getQuizProgress, getScenarioHistory, getClearedCompanies, getCompletedLessons,
} from "@/lib/storage/progress";
import { EMPTY_RECORDS, type LearnerRecords } from "./progress";
import { useOrgContext } from "@/lib/auth/useOrgContext";
import { getReadMarks, syncReadMarks, READ_MARKS_EVENT } from "./readMarks";

export function useLearnerRecords(): { records: LearnerRecords; ready: boolean; userId: string | null; orgId: string | null } {
  const { ready, version } = useProgressSnapshot();
  const { user } = useAuth();
  const userId = user?.id ?? null;
  const { orgId } = useOrgContext();
  const [records, setRecords] = useState<LearnerRecords>(EMPTY_RECORDS);
  const [marksVersion, setMarksVersion] = useState(0);

  useEffect(() => {
    const bump = () => setMarksVersion(v => v + 1);
    window.addEventListener(READ_MARKS_EVENT, bump);
    window.addEventListener("storage", bump);
    return () => {
      window.removeEventListener(READ_MARKS_EVENT, bump);
      window.removeEventListener("storage", bump);
    };
  }, []);

  useEffect(() => {
    if (!ready) return;
    try {
      setRecords({
        rooms: getRoomProgress(),
        quizzes: getQuizProgress(),
        scenarios: new Set(getScenarioHistory().map(s => s.slug)),
        shifts: new Set(getClearedCompanies()),
        lessons: new Set(getCompletedLessons()),
        reads: getReadMarks({ userId, orgId }),
      });
    } catch { /* storage blocked: show the track without progress */ }
  }, [ready, version, marksVersion, userId, orgId]);

  // Studied lessons follow the learner across devices (0111): merge the server's copy once.
  useEffect(() => {
    if (ready && userId) void syncReadMarks({ userId, orgId });
  }, [ready, userId, orgId]);

  return { records, ready, userId, orgId };
}
