/**
 * Human labels for report locations, shared by the screens that publish a location and the
 * triage inbox that shows it. Isomorphic: no React, no answer keys.
 */

export const TASK_TYPE_LABEL: Record<string, string> = {
  reading: "Reading",
  question: "Question",
  log_analysis: "Log analysis",
  flag: "Flag",
  analyst_choice: "Analyst verdict",
  matching: "Matching",
  ordering: "Ordering",
  query_fill: "Query",
  written_report: "Written report",
};

export const KIND_LABEL: Record<string, string> = {
  lesson: "Lesson",
  room_task: "Learning room",
  quiz: "Quiz",
  scenario: "Scenario",
  dashboard: "Live SOC feed",
  other: "Technical",
};

/** What a room task shows the learner first: its heading, else its question / prompt. */
export function taskShown(task: Record<string, unknown> | undefined): string | undefined {
  if (!task) return undefined;
  const t = task as { heading?: string; question?: string; prompt?: string; instructions?: string; scenario?: string; context?: string };
  return t.heading ?? t.question ?? t.prompt ?? t.instructions ?? t.scenario ?? t.context;
}

/** "Chrome 141 on Windows" from a user agent; a short best-effort summary, never the raw string. */
export function browserSummary(ua: string | undefined): string | undefined {
  if (!ua) return undefined;
  const browser = /Edg\/(\d+)/.exec(ua) ? `Edge ${/Edg\/(\d+)/.exec(ua)![1]}`
    : /Firefox\/(\d+)/.exec(ua) ? `Firefox ${/Firefox\/(\d+)/.exec(ua)![1]}`
    : /Chrome\/(\d+)/.exec(ua) ? `Chrome ${/Chrome\/(\d+)/.exec(ua)![1]}`
    : /Version\/(\d+).*Safari/.exec(ua) ? `Safari ${/Version\/(\d+)/.exec(ua)![1]}`
    : "Browser";
  const os = /Windows/.test(ua) ? "Windows" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac OS X/.test(ua) ? "macOS" : /Android/.test(ua) ? "Android" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} on ${os}` : browser;
}
