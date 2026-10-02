// QA H1: the public team feed must not mark attack rows apart from noise by its SHAPE —
// no ATT&CK technique on a raw log (only detections are tagged by real products), no
// empty structured fields; the technique still reaches the report via the answer key.
import { describe, it, expect } from "vitest";
import { buildTeamTimeline } from "./buildTimeline";
import { teamLoad } from "./load";
import { mitreVisible } from "@/lib/sim/mitreVisible";

const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];

describe("public team feed carries no attack tells in its shape", () => {
  for (const company of ["nexacorp", "medcore", "rocketstack", "globallogis", "quantumbank"]) {
    it(company, () => {
      const problems: string[] = [];
      let movedToAnswer = 0;
      for (const diff of ["easy", "medium", "hard"] as const) {
        const tl = buildTeamTimeline(company, diff, `tells-${company}`, null, teamLoad(diff, roster), {});
        for (const t of tl) {
          if (t.channel !== "feed") continue;
          const b = t.body as Record<string, unknown>;
          if ((b.mitre_technique || b.mitre_tactic) && !mitreVisible(b as never)) problems.push(`${b.id}: technique on a raw ${b.source}/${b.event_type} log`);
          for (const [k, v] of Object.entries(b)) {
            if (v === null || (typeof v === "object" && !Array.isArray(v) && Object.keys(v as object).length === 0)) problems.push(`${b.id}: empty field ${k}`);
          }
          if ((t.answer as Record<string, unknown> | undefined)?.mitre_technique) movedToAnswer++;
        }
      }
      expect(problems.slice(0, 10)).toEqual([]);
      expect(movedToAnswer).toBeGreaterThan(0);       // the report still gets the technique back
    });
  }
});
