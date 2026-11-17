import { describe, it, expect } from "vitest";
import type { Ev, RosterMember } from "./types";
import { closeoutOpen, closeoutsOf, detectionPreview, vectorOfTechnique } from "./t3Closeout";
import { nextStep } from "./t3Case";
import { computeReport } from "./report/computeReport";

const T0 = Date.parse("2026-11-16T22:00:00.000Z");
let seq = 0;
const ev = (type: string, sec: number, payload: Record<string, unknown> = {}, actor: string | null = null): Ev =>
  ({ seq: ++seq, type, actor_id: actor, role: null, payload, occurred_at: new Date(T0 + sec * 1000).toISOString() });

describe("stage E: close-out helpers", () => {
  it("maps initial-access techniques to the vector classes", () => {
    expect(vectorOfTechnique("T1566.001")).toBe("email");
    expect(vectorOfTechnique("T1204.002")).toBe("download");
    expect(vectorOfTechnique("T1078")).toBe("account");
    expect(vectorOfTechnique("T1190")).toBe("exposed_service");
    expect(vectorOfTechnique("T1059.001")).toBeNull();
  });
  it("opens after containment starts, and the next step asks for it until sent", () => {
    const e = [
      ev("t3.scope.entity", 1, { entity: "WS-1", state: "confirmed", cites: [1] }),
      ev("forensic.collected", 2, { host: "WS-1", kind: "memory" }),
      ev("t3.scan", 3, { indicator: "1.2.3.4", hosts: [{ host: "WS-1", count: 2 }] }),
      ev("t3.readiness", 4, { verdict: "ready", reason: "one host" }),
    ];
    expect(closeoutOpen(e)).toBe(true);
    expect(nextStep(e).target).not.toBe("closeout");
    e.push(ev("edr.host_isolated", 5, { host: "WS-1" }));
    expect(nextStep(e).target).toBe("closeout");
    e.push(ev("t3.closeout", 6, { vector: "email", first_host: "WS-1", detection: "powershell" }));
    expect(nextStep(e).target).not.toBe("closeout");
    expect(closeoutsOf(e)[0]).toMatchObject({ vector: "email", firstHost: "WS-1" });
  });
  it("previews how many feed logs a detection matches", () => {
    const feed = [ev("feed.event", 1, { id: "a", hostname: "WS-1", description: "powershell -enc AAAA" }), ev("feed.event", 2, { id: "b", hostname: "WS-2", description: "teams update" })];
    expect(detectionPreview(feed, "powershell -enc")).toEqual({ rows: 1, hosts: ["WS-1"] });
    expect(detectionPreview(feed, "ws")).toEqual({ rows: 0, hosts: [] });
  });
});

describe("stage E: the close-out in the report", () => {
  const roster: RosterMember[] = [{ user_id: "instr", role: "instructor", status: "ready", name: "i", handle: null }, { user_id: "x", role: "t3", status: "ready", name: "x", handle: null }];
  const story = () => [
    ev("session.started", 0, {}, "instr"),
    ev("feed.event", 10, { id: "a1", hostname: "WS-1", expected_verdict: "tp", incident_id: "i1", mitre_technique: "T1566.001", mitre_tactic: "Initial Access", user_email: "j.cohen@corp.example", description: "Phishing attachment opened" }),
    ev("feed.event", 20, { id: "a2", hostname: "WS-1", expected_verdict: "tp", incident_id: "i1", mitre_technique: "T1059.001", mitre_tactic: "Execution", description: "powershell -enc beacon to 193.106.191.42" }),
    ev("feed.event", 30, { id: "a3", hostname: "WS-1", expected_verdict: "tp", incident_id: "i1", mitre_technique: "T1053.005", mitre_tactic: "Persistence", description: "schtasks /create Updater" }),
    ev("feed.event", 40, { id: "n1", hostname: "WS-2", expected_verdict: "benign", description: "teams update" }),
  ];
  const cell = (r: ReturnType<typeof computeReport>, label: string) => r.perUser.find(u => u.user_id === "x")!.rubric.find(c => c.label === label);

  it("a right close-out scores 100", () => {
    const e = story();
    const pf = ev("forensic.finding", 50, { kind: "persistence", host: "WS-1", summary: "Scheduled task Updater" }, "x");
    e.push(pf, ev("t3.closeout", 60, { vector: "email", first_host: "ws-1.corp.local", remove: [pf.seq], reset: ["j.cohen"], block: ["193.106.191.42"], detection: "powershell -enc" }, "x"));
    expect(cell(computeReport(e, roster), "Root cause & eradication")).toMatchObject({ value: "100%", score: 12 });
  });
  it("a wrong vector, a benign indicator and a noisy detection lower it", () => {
    const e = story();
    e.push(ev("t3.closeout", 60, { vector: "exposed_service", first_host: "WS-1", reset: ["j.cohen"], block: ["teams"], detection: "update" }, "x"));
    const c = cell(computeReport(e, roster), "Root cause & eradication")!;
    // vector 0, host 1, accounts 1, block 0, persistence 0 (story persisted, nothing removed), detection: 1 attack ("Updater") vs 1 benign = 0.5
    expect(c.value).toBe("42%");
    expect(c.note).toMatch(/entry vector wrong/);
  });
  it("no close-out, no cell", () => {
    expect(cell(computeReport(story(), roster), "Root cause & eradication")).toBeUndefined();
  });
});
