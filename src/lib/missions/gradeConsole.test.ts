// Console steps (room 36): the typed facts and the incidents' state as the learner left them.
import { describe, it, expect } from "vitest";
import { gradeMissionStep } from "./grade";
import { CLEAR_SKY_M0, CLEAR_SKY_M3, CLEAR_SKY_M5 } from "./rooms/clearSky";

const snap = (over: Record<string, unknown> = {}) => ({ status: "New", owner: null, ownerIsMe: false, severity: "High", comments: [], bookmarks: [], ...over });
const problems = (g: ReturnType<typeof gradeMissionStep>) => (g.ok ? (g.reveal.console as { problems: string[] }[]).flatMap(c => c.problems) : []);

describe("console steps", () => {
  const take = CLEAR_SKY_M3.steps.findIndex(s => s.id === "take");
  const record = CLEAR_SKY_M3.steps.findIndex(s => s.id === "record");
  const close = CLEAR_SKY_M5.steps.findIndex(s => s.kind === "console");

  it("right facts are not enough: the incident must be yours and Active", () => {
    const g = gradeMissionStep(CLEAR_SKY_M3, take, { values: { alerts: "3", ip: "198.51.100.23" }, console: { "inc-4412": snap() } }, 1, 0);
    expect(g.ok && g.correct).toBe(false);
    expect(problems(g).join(" ")).toMatch(/not assigned to you/);
    expect(problems(g).join(" ")).toMatch(/Set its status to Active/);
    const ok = gradeMissionStep(CLEAR_SKY_M3, take, { values: { alerts: "3", ip: "198[.]51.100.23" }, console: { "inc-4412": snap({ status: "Active", owner: "You", ownerIsMe: true }) } }, 1, 0);
    expect(ok.ok && ok.correct).toBe(true);
  });

  it("an empty check is not a check", () => {
    const g = gradeMissionStep(CLEAR_SKY_M0, 0, { values: {}, console: {} }, 1, 0);
    expect(g.ok).toBe(false);
  });

  it("the record step wants a bookmark with the proof and a comment with the facts", () => {
    const mine = snap({ status: "Active", owner: "You", ownerIsMe: true });
    const none = gradeMissionStep(CLEAR_SKY_M3, record, { values: {}, console: { "inc-4412": mine } }, 1, 0);
    expect(problems(none).join(" ")).toMatch(/no bookmark/);
    expect(problems(none).join(" ")).toMatch(/no comment from you/);
    const thin = gradeMissionStep(CLEAR_SKY_M3, record, { values: {}, console: { "inc-4412": { ...mine, comments: ["d.okafor was compromised"], bookmarks: [{ name: "b", notes: "", columns: ["IPAddress"], rows: [{ IPAddress: "198.51.100.23" }] }] } } }, 1, 0);
    const said = problems(thin).join(" ");
    expect(said).toMatch(/the account it got into/);
    expect(said).toMatch(/no MFA/);
    expect(said).not.toMatch(/which account was taken/);
  });

  it("closing the NAT incident as a true positive is coached, and either honest classification passes", () => {
    const base = { "inc-4415": snap({ status: "Active", owner: "You", ownerIsMe: true, severity: "Medium", comments: ["Spray got into m.ferreira; second spray 198.51.100.140 missed by the rule"] }) };
    const tp = gradeMissionStep(CLEAR_SKY_M5, close, { values: {}, console: { ...base, "inc-4416": snap({ status: "Closed", classification: "True Positive - suspicious activity", closingComment: "Shop NAT at the shift change, same staff signed in after" }) } }, 1, 0);
    expect(problems(tp).join(" ")).toMatch(/no attacker/);
    for (const c of ["False Positive - incorrect alert logic", "Benign Positive - suspicious but expected"]) {
      const g = gradeMissionStep(CLEAR_SKY_M5, close, { values: {}, console: { ...base, "inc-4416": snap({ status: "Closed", classification: c, closingComment: "Shops' NAT at the 08:00 shift change: the same staff signed in successfully a minute later." }) } }, 1, 0);
      expect(g.ok && g.correct, c).toBe(true);
    }
  });

  it("a NAT trap answer gets its own coaching", () => {
    const step = CLEAR_SKY_M0.steps.findIndex(s => s.id === "entity");
    const g = gradeMissionStep(CLEAR_SKY_M0, step, { values: { app: "Rota Planner", spray: "198.51.100.10" } }, 1, 0);
    const f = g.ok ? (g.reveal.fields as { id: string; say?: string }[]).find(x => x.id === "spray") : undefined;
    expect(f?.say).toMatch(/shops' NAT/);
  });
});
