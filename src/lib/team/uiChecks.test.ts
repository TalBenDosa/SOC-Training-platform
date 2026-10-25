// 2026-10-18 review: escalations said "TI" / "Th external IP"; the report never said where to learn
// what the team missed.
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { rationaleProblem, citableValues } from "./escalationCheck";
import { practiceFor } from "./practice";
import { withPracticeLinks } from "./report/practiceLinks";
import { ROOMS_META } from "@/data/roomsMeta";

const log = { hostname: "SRV-KOK-DC01", src_ip: "176.97.210.93", process: { name: "ntdsutil.exe", cmdline: "ntdsutil \"ac i ntds\" ifm" }, raw: { "winlog.event_data.LogonType": "10" } };

describe("escalation rationale", () => {
  it("rejects the review's real examples", () => {
    expect(rationaleProblem("TI", log, [])).toMatch(/at least/);
    expect(rationaleProblem("Th external IP connecting to the domain controller", log, [])).toMatch(/Cite the evidence/);
  });
  it("accepts a why that names a value from the log or a picked IOC", () => {
    expect(rationaleProblem("RDP logon type 10 to SRV-KOK-DC01 from an external address", log, [])).toBeNull();
    expect(rationaleProblem("ntdsutil.exe creating an IFM copy of the AD database", log, [])).toBeNull();
    expect(rationaleProblem("successful logon from an address on our blocklist", log, [{ value: "176.97.210.93" }])).toMatch(/Cite/);
    expect(rationaleProblem("successful logon from 176.97.210.93, on our blocklist", log, [{ value: "176.97.210.93" }])).toBeNull();
  });
  it("accepts naming an attached IOC by its kind, and suggests a value when it fails (trainee report 2026-10-25)", () => {
    const mail = { user_email: "i.schmidt@sdema.com", src_ip: "5.181.80.66" };
    const iocs = [{ type: "ip", value: "5.181.80.66" }, { type: "domain", value: "client-invoices-portal.info" }];
    expect(rationaleProblem("Can be a phishing email, because of the malicious IP. Need a deeper investigation.", mail, iocs)).toBeNull();
    expect(rationaleProblem("Looks off to me and needs a second opinion from tier two", mail, iocs)).toMatch(/for example 5\.181\.80\.66/);
    expect(rationaleProblem("Can be a phishing email because of the malicious IP address", mail, [])).toMatch(/Cite the evidence/);
  });
  it("collects nested and command-line values", () => {
    expect(citableValues(log)).toEqual(expect.arrayContaining(["srv-kok-dc01", "ntdsutil.exe", "176.97.210.93"]));
  });
});

describe("practice links for missed logs", () => {
  it("maps a technique (or its parent) to a room that practises it", () => {
    const anyTech = ROOMS_META.flatMap(r => r.tasks.map(t => t.mitreTechnique)).find(Boolean)!;
    expect(practiceFor(anyTech)).not.toBeNull();
    expect(practiceFor("T9999")).toBeNull();
    expect(practiceFor(undefined)).toBeNull();
  });
  it("enriches the report's miss lists on the server", () => {
    const anyTech = ROOMS_META.flatMap(r => r.tasks.map(t => t.mitreTechnique)).find(Boolean)!;
    const r = withPracticeLinks({ team: { missedAttackLogs: [{ label: "x", severity: "high", arrivedS: 1, technique: anyTech }] }, perUser: [{ walkedPast: [], falseNegatives: [] }] } as never);
    expect((r.team as unknown as { missedAttackLogs: { practice?: unknown }[] }).missedAttackLogs[0].practice).toBeTruthy();
  });
});
