// Every flag that asks about a value in one of its room's logs must SHOW a log that contains
// that value (2026-10-09 report: "Machine hostname is missing", the flag showed the wrong log).
import { describe, expect, it } from "vitest";
import { ROOMS } from "@/data/rooms";
import { resolveFlagLog } from "./flagLog";

type T = { type: string; id?: string; heading?: string; prompt?: string; event?: unknown; answer?: unknown; logTask?: string };
const json = (x: unknown) => JSON.stringify(x ?? "").toLowerCase();

describe("flag tasks show the log their answer is in", () => {
  it("every flag whose answer is in a room log is shown that log", () => {
    const misses: string[] = [];
    for (const r of ROOMS as unknown as { id: string; tasks: T[] }[]) {
      r.tasks.forEach((t, i) => {
        if (t.type !== "flag") return;
        const ans = String(t.answer ?? "").trim().toLowerCase();
        if (ans.length < 4) return;
        const inSomeLog = r.tasks.some(x => (x.type === "log_analysis" || x.type === "analyst_choice") && json(x.event).includes(ans));
        if (!inSomeLog) return;                                   // a knowledge flag: no log needed
        const shown = resolveFlagLog(r.tasks, i);
        if (!shown || !json(shown).includes(ans)) misses.push(`${r.id}/${t.id}`);
      });
    }
    expect(misses).toEqual([]);
  });

  it("a logTask id pins that task's log even when a later log is nearer", () => {
    const tasks: T[] = [
      { type: "log_analysis", id: "la1", heading: "First", event: { hostname: "A-HOST" } },
      { type: "analyst_choice", id: "ac1", heading: "Verdict", event: { hostname: "B-HOST" } },
      { type: "flag", id: "f", prompt: "Which host?", logTask: "la1" },
    ];
    expect(resolveFlagLog(tasks, 2)).toEqual({ hostname: "A-HOST" });
  });

  it("a heading quoted in the prompt pins that log", () => {
    const tasks: T[] = [
      { type: "log_analysis", id: "la1", heading: "Analysing a Blocked Outbound C2 Connection", event: { hostname: "A-HOST" } },
      { type: "analyst_choice", id: "ac1", heading: "Verdict", event: { hostname: "B-HOST" } },
      { type: "flag", id: "f", prompt: "Go back to the 'Analysing a Blocked Outbound C2 Connection' log. Which host?" },
    ];
    expect(resolveFlagLog(tasks, 2)).toEqual({ hostname: "A-HOST" });
  });
});
