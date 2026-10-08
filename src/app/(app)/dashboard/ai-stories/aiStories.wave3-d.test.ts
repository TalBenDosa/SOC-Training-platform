/**
 * Wave 3 part D (AI stories) — the investigability facts each story must keep.
 * Modelled on aiStories.batch6.test.ts.
 */
import { describe, expect, it } from "vitest";
import { AI_WAVE3_D_STORIES } from "./wave3-d";
import type { TelemetryEvent } from "@/lib/sim/types";

const story = (id: string) => AI_WAVE3_D_STORIES.find(s => s.id === id)!;
const ev = (sid: string, eid: string): TelemetryEvent => story(sid).events.find(e => e.id === eid)!;
const t = (e: TelemetryEvent) => Date.parse(e.ts);
const raw = (e: TelemetryEvent, k: string) => (e.raw as Record<string, unknown>)[k];

const IDS = ["ai-deepfake-exec-call-payment-fraud", "ai-browser-agent-prompt-hijack"];
// Non-baseline attack rows must read like tool output, not a verdict.
const CONCLUSION = /\b(malicious|attacker|exfiltrat\w*|c2|compromised|backdoor|disclosed|stolen|ATLAS)\b/i;

describe("AI stories wave3-d", () => {
  it.each(IDS)("%s exports 8-16 events, chronological, with a detection row and neutral attack text", id => {
    const s = story(id);
    expect(s).toBeTruthy();
    expect(s.events.length).toBeGreaterThanOrEqual(8);
    expect(s.events.length).toBeLessThanOrEqual(16);
    // chronological
    const ts = s.events.map(t);
    expect([...ts].sort((a, b) => a - b)).toEqual(ts);
    // at least one real alert
    expect(s.events.some(e => e.is_detection)).toBe(true);
    // every non-baseline description avoids spoon-fed conclusions
    for (const e of s.events) if (!e.is_baseline) expect(e.description ?? "", e.id).not.toMatch(CONCLUSION);
    // v19: no revoked T1562/T1070.001/.002/T1656/T1672 in structured fields
    for (const e of s.events) {
      const tech = e.mitre_technique ?? "";
      expect(["T1562", "T1656", "T1672", "T1070.001", "T1070.002"], e.id).not.toContain(tech);
    }
    // every event carries a description
    for (const e of s.events) expect(e.description, e.id).toBeTruthy();
  });

  it("deepfake: invite comes from the look-alike domain before the external-tenant meeting record", () => {
    const invite = ev("ai-deepfake-exec-call-payment-fraud", "aidf2");
    expect(raw(invite, "data.office365.SenderFromDomain")).toBe("quantumbank-finance.example");
    expect(invite.event_type).toBe("email_received");
    const meeting = ev("ai-deepfake-exec-call-payment-fraud", "aidf3");
    expect(raw(meeting, "data.office365.Operation")).toBe("MeetingDetail");
    expect(raw(meeting, "data.office365.Workload")).toBe("MicrosoftTeams");
    expect(t(meeting)).toBeGreaterThan(t(invite));
  });

  it("deepfake: the participant record names a foreign organizer tenant and precedes the payment change + rule", () => {
    const part = ev("ai-deepfake-exec-call-payment-fraud", "aidf4");
    expect(raw(part, "data.office365.Operation")).toBe("MeetingParticipantDetail");
    const attendees = raw(part, "data.office365.Attendees") as Array<{ InviterInfo?: { OrganizationId?: string } }>;
    const orgTenant = attendees[0]?.InviterInfo?.OrganizationId;
    const meetingOrg = (raw(ev("ai-deepfake-exec-call-payment-fraud", "aidf3"), "data.office365.Organizer") as { OrganizationId?: string }).OrganizationId;
    expect(orgTenant).toBeTruthy();
    expect(orgTenant).toBe(meetingOrg);
    // the payment-change email and the inbox rule follow the meeting
    expect(t(ev("ai-deepfake-exec-call-payment-fraud", "aidf6"))).toBeGreaterThan(t(part));
    const rule = ev("ai-deepfake-exec-call-payment-fraud", "aidf8");
    expect(raw(rule, "data.office365.Operation")).toBe("New-InboxRule");
    expect(t(rule)).toBeGreaterThan(t(ev("ai-deepfake-exec-call-payment-fraud", "aidf6")));
  });

  it("hijack: consent precedes the service principal and both precede the Graph mail reads", () => {
    const consent = ev("ai-browser-agent-prompt-hijack", "aiba5");
    const sp = ev("ai-browser-agent-prompt-hijack", "aiba6");
    const read = ev("ai-browser-agent-prompt-hijack", "aiba7");
    expect(raw(consent, "azure.auditlogs.operationName")).toBe("Consent to application");
    expect(raw(sp, "azure.auditlogs.operationName")).toBe("Add service principal");
    expect(t(consent)).toBeLessThanOrEqual(t(sp));
    expect(t(sp)).toBeLessThan(t(read));
  });

  it("hijack: the Graph reads use the AppId that was consented to, via MicrosoftGraphActivityLogs", () => {
    const consentAppId = raw(ev("ai-browser-agent-prompt-hijack", "aiba5"), "azure.auditlogs.properties.additionalDetails[0].value");
    const read = ev("ai-browser-agent-prompt-hijack", "aiba7");
    expect(raw(read, "azure.graphactivitylogs.category")).toBe("MicrosoftGraphActivityLogs");
    expect(raw(read, "azure.graphactivitylogs.properties.app_id")).toBe(consentAppId);
    expect(String(raw(read, "azure.graphactivitylogs.properties.request_uri"))).toContain("graph.microsoft.com");
    // the app-governance detection names the same AppId
    const alert = ev("ai-browser-agent-prompt-hijack", "aiba10");
    expect(alert.is_detection).toBe(true);
    expect(raw(alert, "ExtendedProperties.AppId")).toBe(consentAppId);
    expect(raw(alert, "ProductName")).toBe("Microsoft Defender for Cloud Apps");
  });
});
