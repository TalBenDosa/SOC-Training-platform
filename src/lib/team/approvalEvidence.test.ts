/**
 * Scenario review 2026-10-01, fix 5: an FP decoy that rests on an approval must
 * have that approval in the feed — otherwise escalating it (the right call without
 * evidence) is graded wrong. r.williams' 9.3 GB USB copy cited "JIRA FIN-2847",
 * which never appeared anywhere.
 */
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { buildTeamTimeline, approvalRefOf } from "./buildTimeline";
import { teamLoad } from "./load";

describe("approval references", () => {
  it.each([
    ["covered by approved request RITM0048213.", "RITM0048213"],
    ["requested the forward via IT ticket INC-90123, approved by manager", "INC-90123"],
    ["for s.kim's parental leave (ticket HR-2026-117)", "HR-2026-117"],
    ["approved for the annual EY audit. Reference GL-AUDIT-2026-03.", "GL-AUDIT-2026-03"],
    ["pre-approved for m.huber's sabbatical (QB-HR-2026-S14).", "QB-HR-2026-S14"],
    ["the request came from WS-FIN-2847 itself", null],               // a hostname, not a ticket
    ["approved by the manager — no reference", null],
  ])("%s → %s", (text, ref) => expect(approvalRefOf(text)).toBe(ref));
});

describe("team feed", () => {
  it("every approval-based decoy is preceded by its approved ServiceNow request", () => {
    let checked = 0;
    for (const company of ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"]) {
      for (const seed of ["a", "b", "c", "d"]) {
        const tl = buildTeamTimeline(company, "hard", seed, null, teamLoad("hard", [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }]))
          .filter(e => e.channel === "feed");
        tl.forEach((e, i) => {
          const a = e.answer as { expected_verdict?: string; fp_explanation?: string } | undefined;
          if (a?.expected_verdict !== "fp") return;
          const ref = approvalRefOf(a.fp_explanation);
          if (!ref) return;
          checked++;
          const at = tl.findIndex(x => (x.body.raw as Record<string, unknown> | undefined)?.["servicenow.number"] === ref);
          expect(at, `${company}/${seed}: ${ref}`).toBeGreaterThanOrEqual(0);
          expect(at).toBeLessThan(i);
          const rec = tl[at].body as { raw: Record<string, unknown>; description: string };
          expect(rec.raw["servicenow.approval"]).toBe("Approved");
          expect(rec.description).toContain(ref);
        });
      }
    }
    expect(checked).toBeGreaterThan(0);
  });
});
