/**
 * The scenario page must show every log with a readable, Live-SOC-style
 * description (user report 2026-09-28: rows read "email_received", a bare file
 * path or a domain). The page withholds the authored description + MITRE, so
 * the line is built from observable fields only — check it for every event of
 * every scenario, exactly as the browser receives it.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { SCENARIOS } from "./scenarios";
import { describeEvent, describeEventForRow } from "./describeEvent";
import type { TelemetryEvent } from "./types";
import { AI_WAVE3_B_STORIES } from "@/app/(app)/dashboard/ai-stories/wave3-b";

type Built = { slug: string; events: TelemetryEvent[] };
const built: Built[] = (SCENARIOS as unknown as { slug: string; build?: () => { events?: TelemetryEvent[] }; events?: TelemetryEvent[] }[])
  .map(s => ({ slug: s.slug, events: (typeof s.build === "function" ? s.build().events : s.events) ?? [] }));

/** What page.tsx sends to the browser (F-02): no authored description / MITRE. */
const stripped = (e: TelemetryEvent): TelemetryEvent => ({ ...e, description: undefined, mitre_technique: undefined, mitre_tactic: undefined });

describe("scenario log descriptions (Live-SOC style)", () => {
  it("every event gets a real sentence, never the raw event_type or a bare field", () => {
    const bad: string[] = [];
    for (const s of built) for (const e of s.events) {
      const d = describeEvent(stripped(e), { preferFields: true });
      const et = e.event_type.replace(/_/g, " ");
      const generic = d.toLowerCase() === et || d.toLowerCase().startsWith(`${et} on `)
        || /^(Process Create|DNS query)\.?$/.test(d);
      if (!d.trim() || generic || d === e.event_type || /^[a-z]+(_[a-z]+)+$/.test(d)) bad.push(`${s.slug}/${e.id}: ${d}`);
    }
    expect(bad).toEqual([]);
  });

  it("never reuses the authored (answer-bearing) description for attack events", () => {
    for (const s of built) for (const e of s.events) {
      if (!e.description || !e.mitre_technique) continue;
      expect(describeEvent(e)).not.toBe(e.description);
    }
  });

  it("splits the user onto its own line like the live feed", () => {
    const r = describeEventForRow({ id: "x", ts: "2026-01-01T00:00:00Z", source: "email_gateway", event_type: "email_received", user_email: "j.chen@nexacorp.com" } as TelemetryEvent);
    expect(r).toEqual({ user: "j.chen", title: undefined, action: "Received an email" });
  });
});

/**
 * Review 2026-11-08 (Sdema exercise, K3): the row line named the wrong actor ("y.mendes performed
 * Reset password (by admin)" for the help desk agent's change), hid detections ("g.rossi browsed to
 * a website" for a Prompt Shields DocumentAttack, "203.0.113.47 made a cloud API call" for a Defender
 * for Cloud alert) and gave no sender for an outbound mail ("System sent an email").
 */
describe("the team row line names what the record names", () => {
  const team = (e: Partial<TelemetryEvent>) => describeEvent({ id: "x", ts: "2026-01-01T08:00:00Z", ...e } as TelemetryEvent, { preferFields: true, fieldsOnly: true });

  it("a directory change names its actor and its target", () => {
    const raw = {
      "azure.auditlogs.operationName": "Reset password (by admin)",
      "azure.auditlogs.properties.initiatedBy.user.userPrincipalName": "z.yilmaz@sdemagroup.com",
      "azure.auditlogs.properties.targetResources[0].userPrincipalName": "y.mendes@sdemagroup.com",
    };
    expect(team({ source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify", user_email: "y.mendes@sdemagroup.com", raw }))
      .toBe("z.yilmaz reset the password of y.mendes");
    expect(team({ source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify", user_email: "y.mendes@sdemagroup.com",
      raw: { ...raw, "azure.auditlogs.operationName": "Admin deleted security info" } })).toBe("z.yilmaz deleted the security info of y.mendes");
    expect(team({ source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify", user_email: "y.mendes@sdemagroup.com",
      raw: { ...raw, "azure.auditlogs.operationName": "Change user password", "azure.auditlogs.properties.initiatedBy.user.userPrincipalName": "y.mendes@sdemagroup.com" } }))
      .toBe("y.mendes changed their password");
  });

  it("an API Management gateway row reads the Prompt Shields verdict from the logged backend response, never as browsing", () => {
    // The RAG story's Prompt Shields rows (ai-stories/wave3-b.ts shieldPromptCall).
    let seen = 0;
    for (const s of AI_WAVE3_B_STORIES) for (const e of s.events) {
      if (e.raw?.Type !== "ApiManagementGatewayLogs") continue;
      seen++;
      const line = describeEvent(e, { preferFields: true, fieldsOnly: true });
      expect(line).not.toMatch(/browsed/);
      expect(line).toMatch(/^Prompt Shields \(shieldPrompt\): userPromptAnalysis attackDetected false; documentsAnalysis attackDetected (true|false), assist-support-chat$/);
    }
    expect(seen).toBeGreaterThan(0);
    const raw = { Type: "ApiManagementGatewayLogs", ApimSubscriptionId: "assist-support-chat", OperationId: "shieldPrompt", ResponseCode: 200,
      BackendResponseBody: "{\"userPromptAnalysis\":{\"attackDetected\":false},\"documentsAnalysis\":[{\"attackDetected\":true}]}" };
    expect(team({ source: "cloud_azure", vendor: "Azure API Management", event_type: "http_request", raw }))
      .toBe("Prompt Shields (shieldPrompt): userPromptAnalysis attackDetected false; documentsAnalysis attackDetected true, assist-support-chat");
    expect(team({ source: "cloud_azure", vendor: "Azure API Management", event_type: "http_request", raw: { ...raw, OperationId: "chatCompletions", ApiId: "openai", Method: "POST" } }))
      .toBe("API Management POST openai/chatCompletions for assist-support-chat: HTTP 200");
  });

  it("a mail row names its sender and recipient", () => {
    expect(team({ source: "email_gateway", vendor: "Microsoft Defender for Office 365", event_type: "email_sent",
      raw: { "email.from.address": "y.mendes@sdemagroup.com", "email.to.address": "archive@proton.me" } })).toBe("y.mendes sent an email to archive@proton.me");
    expect(team({ source: "email_gateway", event_type: "email_received", user_email: "j.chen@nexacorp.com", raw: { "email.from.address": "billing@vendor.example" } }))
      .toBe("j.chen received an email from billing@vendor.example");
  });

  it("detections read as detections, with the product's own name", () => {
    expect(team({ source: "siem", vendor: "Azure AI Content Safety", event_type: "http_request", is_detection: true, user_email: "g.rossi@sdemagroup.com",
      raw: { "promptshields.attack_type": "DocumentAttack", "promptshields.classification": "AttackDetected", "gateway.application": "assist-support-chat" } }))
      .toBe("Prompt Shields: DocumentAttack, AttackDetected (g.rossi, assist-support-chat)");
    expect(team({ source: "cloud_azure", vendor: "Microsoft Defender for Cloud", event_type: "cloud_api_call", is_detection: true, src_ip: "203.0.113.47",
      raw: { "azure.alert.displayName": "ASCII Smuggling prompt injection detected" } })).toBe("Alert: ASCII Smuggling prompt injection detected");
    expect(team({ source: "firewall", vendor: "Palo Alto Networks", event_type: "ids_blocked", src_ip: "185.220.101.45", dst_ip: "10.10.20.2", dst_port: 445,
      raw: { "panw.threatid": "40001", "panw.category": "brute-force" } })).toBe("Threat ID 40001, brute-force from 185.220.101.45 to 10.10.20.2:445");
  });

  it("a mail or alert value that states the conclusion falls back to the plain line", () => {
    expect(team({ source: "email_gateway", event_type: "email_received", user_email: "j.chen@nexacorp.com", raw: { "email.from.address": "ransomware@x.example" } }))
      .toBe("j.chen received an email");
  });
});
