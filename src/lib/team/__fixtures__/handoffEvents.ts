// A small shift with every kind of hand-off: a Tier-1 escalation with ten indicators and a log
// added later, a Tier-2 report with scope, an elevation, a containment and an isolation request.
import type { Ev } from "../types";

export const at = (m: number) => new Date(Date.UTC(2026, 10, 8, 9, m)).toISOString();
export const names: Record<string, string> = { u1: "Dana", u2: "Noa", u3: "Avi", u4: "Maya" };
export const nameOf = (id: string | null) => (id ? names[id] ?? "Analyst" : "Analyst");

export const log = {
  id: "e1", ts: at(0), source: "edr", vendor: "CrowdStrike", event_type: "process_creation", severity: "high",
  description: "Encoded PowerShell spawned by WINWORD.EXE", hostname: "WS-FIN-2847", user_email: "r.cohen@nexacorp.com",
  src_ip: "10.1.2.3", dst_ip: "185.220.101.4", process: { name: "powershell.exe", cmdline: "powershell -enc SQBFAFgA" },
  raw: { CommandLine: "powershell -enc SQBFAFgA" },
  // Answer-key fields never reach a player's payload; even if one did, the hand-off must not show it.
  expected_verdict: "tp", fp_explanation: "THE ANSWER",
};
export const iocs = Array.from({ length: 10 }, (_, i) => ({ type: "ip", value: `185.220.101.${i + 1}`, source: "picked" }));

export const sampleEvents = (): Ev[] => [
  { seq: 1, type: "feed.event", actor_id: null, role: null, payload: log, occurred_at: at(0) },
  { seq: 2, type: "feed.event", actor_id: null, role: null, payload: { id: "e2", ts: at(1), description: "Beacon to 185.220.101.4", hostname: "WS-FIN-2847", source: "firewall", severity: "high" }, occurred_at: at(1) },
  { seq: 3, type: "disposition.set", actor_id: "u1", role: "t1", payload: { event_id: "e1", verdict: "true_positive" }, occurred_at: at(2) },
  { seq: 4, type: "escalation.requested", actor_id: "u1", role: "t1", occurred_at: at(3), payload: {
    event_id: "e1", summary: "Ticket INC0033424 (New): Locked out, then an encoded PowerShell beacon on WS-FIN-2847 right after the user's password reset",
    observations: "WINWORD.EXE spawned powershell -enc, which decodes to an IEX download cradle. The host then beaconed every 60s to 185.220.101.4.",
    assessment: "Macro dropper with C2", severity: "high", requested_action: "contain", confidence: 0.7, iocs,
    hostname: "WS-FIN-2847", entity: "WS-FIN-2847", recommend_isolation: true, snapshot: log } },
  { seq: 5, type: "evidence.pinned", actor_id: "u1", role: "t1", payload: { event_id: "e2", case_event_id: "e1", label: "Beacon to 185.220.101.4", attached: true }, occurred_at: at(4) },
  { seq: 6, type: "escalation.acknowledged", actor_id: "u2", role: "t2", payload: { event_id: "e1" }, occurred_at: at(5) },
  { seq: 7, type: "report.submitted", actor_id: "u2", role: "t2", occurred_at: at(6), payload: { event_id: "e1", summary: "Macro C2 on WS-FIN-2847", findings: "Confirmed the beacon in the EDR, one host only.", verdict: "true_positive", recommendation: "Isolate the host, block 185.220.101.4", incident: "INC-A" } },
  { seq: 8, type: "scope.set", actor_id: "u2", role: "t2", payload: { incident: "INC-A", hosts: ["WS-FIN-2847"], users: ["r.cohen@nexacorp.com"], techniques: ["T1059.001"] }, occurred_at: at(7) },
  { seq: 9, type: "elevation.requested", actor_id: "u2", role: "t2", occurred_at: at(8), payload: { event_id: "e1", summary: "Macro C2 on WS-FIN-2847", hunt_ask: "Hunt lateral movement from WS-FIN-2847 to the DC", t2_verdict: "true_positive", t2_findings: "Confirmed the beacon", t2_recommendation: "Isolate", iocs, hostname: "WS-FIN-2847", snapshot: log } },
  { seq: 10, type: "containment.requested", actor_id: "u2", role: "t2", occurred_at: at(9), payload: { event_id: "e1", target: "r.cohen@nexacorp.com", containment_type: "disable_account", reason: "Credentials used from the beacon host", asset_criticality: "standard", blast_radius: "The user loses mail for an hour", business_owner: "Finance, business hours", incident: "INC-A" } },
  { seq: 11, type: "isolation.requested", actor_id: "u2", role: "t2", occurred_at: at(10), payload: { host: "WS-FIN-2847", reason: "Macro C2 on WS-FIN-2847. What breaks: payroll run. standard asset", incident: "INC-A", case: "e1" } },
];

