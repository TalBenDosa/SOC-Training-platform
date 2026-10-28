import { describe, it, expect } from "vitest";
import { gradeTimelineReport, sanitizeTimelineReport, type TimelineReport, type TruthEvent } from "./timelineReport";

// A phishing macro → PowerShell download → DLL loader with C2, as the feed shows it.
const truth: TruthEvent[] = [
  { id: "a1", ts: "2026-10-28T09:12:00Z", source: "email_gateway", stage: "T1566.001", host: undefined, users: ["d.levi@nexacorp.com"], actors: [], ips: [], domains: ["invoice-nexa.com"], files: ["invoice_0928.docm"] },
  { id: "a2", ts: "2026-10-28T09:16:02Z", source: "edr", stage: "T1059.001", host: "WS-FIN-3041", users: ["NEXA\\d.levi"], actors: ["powershell.exe", "WINWORD.EXE"], ips: [], domains: [], files: [], cmd: "powershell.exe -nop -w hidden -enc SQBFAFgA" },
  { id: "a3", ts: "2026-10-28T09:16:40Z", source: "proxy", stage: "T1105", host: "WS-FIN-3041", users: ["NEXA\\d.levi"], actors: ["powershell.exe"], ips: ["45.137.22.81"], domains: ["cdn-invoice-nexa.com"], files: ["u.dll"] },
  { id: "a4", ts: "2026-10-28T09:17:30Z", source: "edr", stage: "T1218.011", host: "WS-FIN-3041", users: ["NEXA\\d.levi"], actors: ["rundll32.exe", "powershell.exe"], ips: ["45.137.22.81"], domains: [], files: ["9f2c4e7a1b9f2c4e7a1b9f2c4e7a1b9f2c4e7a1b9f2c4e7a1b9f2c4e7a1bd03e"], cmd: "rundll32.exe u.dll,Start" },
];
const realIndicators = ["d.levi@nexacorp.com", "WS-FIN-3041", "45.137.22.81", "cdn-invoice-nexa.com", "invoice-nexa.com", "9f2c4e7a1b9f2c4e7a1b9f2c4e7a1b9f2c4e7a1b9f2c4e7a1b9f2c4e7a1bd03e"];
const evidenceText = JSON.stringify([...truth, { id: "n1", hostname: "WS-HR-1102", src_ip: "10.0.4.12" }]);

const full: TimelineReport = {
  rows: [
    { id: "1", eventId: "a1", time: "09:12:00", host: "", actor: "d.levi@nexacorp.com", action: "Phishing email with a macro document delivered" },
    { id: "2", eventId: "a2", time: "09:16:02", host: "WS-FIN-3041", actor: "NEXA\\d.levi", action: "WINWORD started encoded PowerShell (macro)" },
    { id: "3", eventId: "a3", time: "09:16:40", host: "WS-FIN-3041", actor: "powershell.exe", action: "Downloaded u.dll from cdn-invoice-nexa.com" },
    { id: "4", eventId: "a4", time: "09:17:30", host: "WS-FIN-3041", actor: "NEXA\\d.levi", action: "rundll32 ran u.dll, beacons to 45.137.22.81" },
  ],
  iocs: [
    { id: "i1", value: "invoice-nexa.com", role: "phishing" },
    { id: "i2", value: "45.137.22.81", role: "c2" },
    { id: "i3", value: "NEXA\\d.levi", role: "compromised_account" },
    { id: "i4", value: "WS-FIN-3041", role: "compromised_host" },
  ],
  summary: "Phishing macro ran PowerShell, dropped a DLL loader and opened a C2 beacon on a finance workstation.",
  done: "Blocked both domains and the C2 IP on the proxy",
  open: "Did the loader reach other hosts?",
  next: "Isolate WS-FIN-3041 and reset d.levi",
};
const grade = (report: TimelineReport, difficulty: "easy" | "medium" | "hard" = "medium") =>
  gradeTimelineReport({ report, truth, realIndicators, evidenceText, attackTitle: "Macro document to DLL loader with C2 beacon", mitre: ["T1566.001", "T1059.001", "T1105", "T1218.011"], difficulty });

describe("timeline report grader", () => {
  it("passes a complete end-to-end report at every difficulty", () => {
    for (const d of ["easy", "medium", "hard"] as const) {
      const g = grade(full, d);
      expect(g.passed, `${d}: ${g.requirements.join(" | ")}`).toBe(true);
      expect(g.score).toBeGreaterThanOrEqual(85);
    }
  });

  it("does not pass keywords plus indicators without a timeline", () => {
    const g = grade({ ...full, rows: [] });
    expect(g.passed).toBe(false);
    expect(g.checks[0].title).toMatch(/timeline is empty/);
  });

  it("counts coverage per stage and points at the gap without naming it", () => {
    const g = grade({ ...full, rows: full.rows.slice(0, 2) });
    const cov = g.checks.find(c => c.title.startsWith("Coverage"));
    expect(cov?.title).toBe("Coverage: 2 of 4 attack stages.");
    expect(cov?.detail).toMatch(/gap after 09:16:02/);
    expect(cov?.detail).not.toMatch(/rundll32|u\.dll|45\.137/);
    expect(g.passed).toBe(false); // medium needs 60% of the stages
    expect(grade({ ...full, rows: full.rows.slice(0, 2) }, "easy").passed).toBe(true); // easy: half is enough
  });

  it("flags swapped steps, and hard requires the right order", () => {
    const swapped = { ...full, rows: [full.rows[0], full.rows[2], full.rows[1], full.rows[3]] };
    const g = grade(swapped, "hard");
    expect(g.checks.some(c => /Order: rows 2 and 3/.test(c.title))).toBe(true);
    expect(g.passed).toBe(false);
  });

  it("flags a row whose host or account does not match its log", () => {
    const g = grade({ ...full, rows: full.rows.map(r => (r.id === "4" ? { ...r, host: "WS-HR-1102", actor: "j.cohen" } : r)) });
    expect(g.checks.some(c => /row 4 doesn't match/.test(c.title))).toBe(true);
  });

  it("ties a typed row to a log by a value it quotes", () => {
    const typed = { ...full, rows: [...full.rows.slice(0, 3), { id: "t", time: "09:17", host: "WS-FIN-3041", actor: "rundll32.exe", action: "rundll32 loaded the DLL and called out to 45.137.22.81" }] };
    expect(grade(typed).checks.find(c => c.title.startsWith("Coverage"))?.title).toMatch(/all 4/);
  });

  it("catches invented values, feed noise and wrong roles", () => {
    const g = grade({ ...full, iocs: [
      { id: "a", value: "6.6.6.6", role: "c2" },
      { id: "b", value: "10.0.4.12", role: "attacker_ip" },
      { id: "c", value: "45.137.22.81", role: "compromised_account" },
    ] });
    expect(g.passed).toBe(false);
    expect(g.checks.some(c => /Couldn't verify: "6\.6\.6\.6"/.test(c.title))).toBe(true);
    expect(g.checks.some(c => /10\.0\.4\.12 is in the feed but not part of this attack/.test(c.title))).toBe(true);
    expect(g.checks.some(c => /Role doesn't fit: 45\.137\.22\.81/.test(c.title))).toBe(true);
  });

  it("hard needs a next step that stops the attack", () => {
    const g = grade({ ...full, next: "Write a ticket and watch the user mailbox for a week" }, "hard");
    expect(g.passed).toBe(false);
    expect(g.requirements).toContain("Recommend a next step that stops this attack.");
  });

  it("cannot pass before an attack is in the feed", () => {
    const g = gradeTimelineReport({ report: full, truth: [], realIndicators: [], evidenceText: "", mitre: [], difficulty: "easy" });
    expect(g.passed).toBe(false);
    expect(g.feedback).toMatch(/no open incident/);
  });

  it("sanitizes an untrusted body", () => {
    const r = sanitizeTimelineReport({ rows: [{ id: 5, action: "x".repeat(5000) }, null], iocs: [{ value: "1.2.3.4", role: "admin" }], summary: 7 });
    expect(r.rows).toHaveLength(2);
    expect(r.rows[0].action.length).toBe(1200);
    expect(r.iocs[0].role).toBe("");
    expect(r.summary).toBe("");
  });
});
