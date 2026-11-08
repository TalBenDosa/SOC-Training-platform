// A Sentinel incident opened from an escalation opens with the analyst's report (owner, 2026-11-08):
// the title is their own summary (no generic prefix), the description and the first comment are
// their report, and their indicators are entities of the incident. Built from a real team timeline.
import { describe, it, expect, afterEach } from "vitest";
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { Ev } from "@/lib/team/types";
import { buildWorkspace } from "@/lib/sentinel/workspace";
import { foldIncidentState } from "@/lib/sentinel/state";
import { escalatedCases } from "@/lib/team/investigationConsole";
import { IncidentDescription } from "./IncidentDescription";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const roster = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
const events: TelemetryEvent[] = buildTeamTimeline("nexacorp", "hard", "handoff-1", null, teamLoad("hard", roster), {})
  .filter(t => t.channel === "feed").map(t => t.body as unknown as TelemetryEvent);
const names: Record<string, string> = { u1: "Dana" };
const nameOf = (id: string | null) => (id ? names[id] ?? "Analyst" : "Analyst");

const SUMMARY = "Ticket INC0033424 (New): Locked out, then logons from a new country minutes after the reset";
const OBS = "The user called the help desk locked out, then a sign-in from 203.0.113.77 succeeded with the new password.";

function escalate(ev: TelemetryEvent, seq: number): Ev[] {
  return [
    { seq, type: "feed.event", actor_id: null, role: null, payload: ev as unknown as Record<string, unknown>, occurred_at: ev.ts },
    { seq: seq + 1, type: "escalation.requested", actor_id: "u1", role: "t1", occurred_at: ev.ts, payload: {
      event_id: ev.id, summary: SUMMARY, observations: OBS, assessment: "Account takeover", severity: "high", requested_action: "investigate", confidence: 0.7,
      disposition: "true_positive", iocs: [{ type: "ip", value: "203.0.113.77", source: "manual" }, { type: "domain", value: "login-nexacorp-support.com", source: "manual" }],
      hostname: ev.hostname, snapshot: ev } },
  ];
}

let root: Root | null = null; let el: HTMLDivElement | null = null;
afterEach(() => { act(() => root?.unmount()); el?.remove(); root = null; el = null; });

describe("Sentinel: an escalated incident", () => {
  const plain = buildWorkspace(events, { companyId: "nexacorp" });
  const raised = new Set(Object.values(plain.alertEventIds).flat());
  const quiet = events.find(e => !raised.has(e.id))!;
  const log = escalate(quiet, 1000);
  const ws = buildWorkspace(events, { companyId: "nexacorp", escalated: escalatedCases(log, nameOf) });
  const inc = ws.incidents.find(i => i.alertIds.some(a => (ws.alertEventIds[a] ?? []).includes(quiet.id)))!;

  it("is titled with the analyst's own summary, in full", () => {
    expect(inc).toBeTruthy();
    expect(inc.title).toBe(SUMMARY);
    expect(inc.title).not.toMatch(/^Escalated for investigation/);
  });

  it("carries the report in its description and as the first comment, by the analyst", () => {
    expect(inc.description).toContain("Escalation from Dana (Tier-1)");
    expect(inc.description).toContain(`Observations: ${OBS}`);
    expect(inc.description).toContain("Verdict: true positive");
    expect(inc.description).toContain("Indicators (2): ip: 203.0.113.77, domain: login-nexacorp-support.com");
    const st = foldIncidentState([], inc);
    expect(st.comments[0]).toMatchObject({ author: "Dana" });
    expect(st.comments[0].text).toContain(OBS);
    expect(st.activity.some(a => a.text === "Escalated by Dana (Tier-1)")).toBe(true);
    // The KQL table says the same.
    const row = ws.tables.SecurityIncident.rows.find(r => r.IncidentName === inc.id)!;
    expect(row.Title).toBe(SUMMARY);
    expect(String(row.Description)).toContain(OBS);
  });

  it("names the analyst's indicators as entities", () => {
    const names = inc.entityIds.map(id => ws.entities[id]?.name);
    expect(names).toContain("203.0.113.77");
    expect(names).toContain("login-nexacorp-support.com");
    expect(ws.entities["ip:203.0.113.77"].info["Named in escalation"]).toBe("Yes");
  });

  it("keeps every other incident's number", () => {
    for (const i of plain.incidents) expect(ws.incidents.find(x => x.id === i.id)?.number ?? i.number).toBe(i.number);
  });

  it("a rule-raised incident that was escalated leads with the report and keeps the detection's description", () => {
    const loud = events.find(e => raised.has(e.id) && plain.incidents.some(i => i.alertIds.some(a => (plain.alertEventIds[a] ?? []).includes(e.id))))!;
    const ws2 = buildWorkspace(events, { companyId: "nexacorp", escalated: escalatedCases(escalate(loud, 2000), nameOf) });
    const inc2 = ws2.incidents.find(i => i.alertIds.some(a => (ws2.alertEventIds[a] ?? []).includes(loud.id)))!;
    const before = plain.incidents.find(i => i.id === inc2.id)!;
    expect(inc2.title).toBe(before.title);
    expect(inc2.description.startsWith("Escalation from Dana (Tier-1)")).toBe(true);
    expect(inc2.description).toContain(`Detection: ${before.description}`);
    expect(inc2.detectionDescription).toBe(before.description);
  });

  it("the incident page opens with the structured report", async () => {
    el = document.createElement("div"); document.body.appendChild(el); root = createRoot(el);
    await act(async () => root!.render(React.createElement(IncidentDescription, { incident: inc })));
    const t = el.textContent ?? "";
    expect(t).toContain("Escalated by the analyst");
    expect(t).toContain(SUMMARY);
    expect(t).toContain(OBS);
    expect(t).toContain("203.0.113.77");
    expect(t).toContain("Verdict: true positive");
    expect(el.querySelector("[data-handoff-summary]")?.className).toContain("st-ho-summary");
  });
});
