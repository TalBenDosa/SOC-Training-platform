/**
 * Rooms whose labs have passed the lab-clarity pass (learner feedback, 2026-11-24: "I did not
 * understand what the lab is for"). For every room here, labClarity.test.ts requires each lab to
 * carry `teaches` (why the lab exists) and a `primer` (what to know first, with a worked example).
 * When every room is listed, the test switches to all rooms.
 *
 * MERGE-SAFE REGISTRY: one room id per line (merge=union in .gitattributes).
 */
export const LAB_CLARITY_ROOMS: ReadonlySet<string> = new Set([
  "sharepoint-teams-monitoring",
]);
