/**
 * Wave-3 part B (prompt-injection AI stories) - the facts each story must keep investigable.
 * Modelled on aiStories.batch6: an alert row exists, attack-row descriptions stay neutral,
 * chronology holds where it carries meaning, and the key vendor-native fields are present.
 */
import { describe, expect, it } from "vitest";
import { AI_WAVE3_B_STORIES } from "./wave3-b";
import type { TelemetryEvent } from "@/lib/sim/types";

const story = (id: string) => AI_WAVE3_B_STORIES.find(s => s.id === id)!;
const ev = (sid: string, eid: string): TelemetryEvent => story(sid).events.find(e => e.id === eid)!;
const t = (e: TelemetryEvent) => Date.parse(e.ts);
const raw = (e: TelemetryEvent, k: string) => (e.raw as Record<string, unknown>)[k];

const IDS = ["ai-rag-chatbot-document-injection", "ai-stored-injection-copilot-kb"];
const CONCLUSION = /\b(malicious|attacker|exfiltrat\w*|c2|compromised|backdoor|stolen|poisoned|fraud\w*)\b/i;

describe("AI stories wave3-B", () => {
  it("both stories are registered with the assigned tier and companies", () => {
    expect(AI_WAVE3_B_STORIES.map(s => s.id).sort()).toEqual([...IDS].sort());
    for (const s of AI_WAVE3_B_STORIES) expect(s.complexity).toBe("core");
    expect(story("ai-rag-chatbot-document-injection").companies).toEqual(["nexacorp", "medcore"]);
    expect(story("ai-stored-injection-copilot-kb").companies).toEqual(["nexacorp", "medcore", "globallogis", "quantumbank"]);
    expect(story("ai-stored-injection-copilot-kb").soloCompanies).toEqual(["nexacorp", "quantumbank"]);
  });

  it.each(IDS)("%s has a detection row, 8-16 events, and neutral attack-row descriptions", id => {
    const s = story(id);
    expect(s.events.length).toBeGreaterThanOrEqual(8);
    expect(s.events.length).toBeLessThanOrEqual(16);
    expect(s.events.some(e => e.is_detection)).toBe(true);
    for (const e of s.events) {
      expect(e.description, e.id).toBeTruthy();
      if (!e.is_baseline && !e.is_detection) expect(e.description ?? "", e.id).not.toMatch(CONCLUSION);
    }
  });

  it.each(IDS)("%s events are ordered by ts except baselines", id => {
    let prev = -Infinity;
    for (const e of story(id).events) {
      if (!e.is_baseline) { expect(t(e), e.id).toBeGreaterThanOrEqual(prev); prev = t(e); }
    }
  });

  it("RAG: the uploaded blob, the grounding document and the Defender alert line up", () => {
    const upload = ev("ai-rag-chatbot-document-injection", "airag2");
    expect(raw(upload, "OperationName")).toBe("PutBlob");
    expect(raw(upload, "AuthenticationType")).toBe("DelegationSas");
    // the user delegation SAS was signed with the key the app's managed identity requested just before
    const key = ev("ai-rag-chatbot-document-injection", "airag1b");
    expect(raw(key, "OperationName")).toBe("GetUserDelegationKey");
    expect(raw(key, "AuthenticationType")).toBe("OAuth");
    expect(raw(upload, "RequesterObjectId")).toBe(raw(key, "RequesterObjectId"));
    expect(t(key)).toBeLessThan(t(upload));
    expect(upload.file?.name).toBe("acme-vendor-quote-2026.pdf");
    // the app's managed-identity read (GetBlob) names the same ObjectKey as the upload
    const read = ev("ai-rag-chatbot-document-injection", "airag6");
    expect(raw(read, "OperationName")).toBe("GetBlob");
    expect(raw(read, "ObjectKey")).toBe(raw(upload, "ObjectKey"));
    // the document-attack signal is the Prompt Shields response the gateway logged (Content Safety's
    // own resource log carries no verdict), and the same check on an ordinary day said false
    const ps = ev("ai-rag-chatbot-document-injection", "airag5");
    expect(raw(ps, "Type")).toBe("ApiManagementGatewayLogs");
    expect(JSON.parse(String(raw(ps, "BackendResponseBody")))).toEqual({ userPromptAnalysis: { attackDetected: false }, documentsAnalysis: [{ attackDetected: true }] });
    const base = ev("ai-rag-chatbot-document-injection", "airag1c");
    expect(JSON.parse(String(raw(base, "BackendResponseBody"))).documentsAnalysis[0].attackDetected).toBe(false);
    expect(Object.keys(base.raw ?? {}).sort()).toEqual(Object.keys(ps.raw ?? {}).sort());
    // the anonymous chat names no employee
    for (const e of story("ai-rag-chatbot-document-injection").events) expect(e.user_email ?? "", e.id).not.toMatch(/@/);
    // the Defender for Cloud alert is the real AI.Azure_ASCIISmuggling name
    const dfc = ev("ai-rag-chatbot-document-injection", "airag7");
    expect(raw(dfc, "azure.alert.alertType")).toBe("AI.Azure_ASCIISmuggling");
    expect(raw(dfc, "azure.alert.displayName")).toBe("ASCII Smuggling prompt injection detected");
    expect(dfc.severity).toBe("high");
  });

  it("RAG: each alert's time span is the span of the rows it covers", () => {
    const sid = "ai-rag-chatbot-document-injection";
    const sent = ev(sid, "airag9"), dfc = ev(sid, "airag7");
    expect(raw(sent, "StartTime")).toBe(ev(sid, "airag2").ts);
    expect(raw(sent, "EndTime")).toBe(ev(sid, "airag8").ts);
    expect(raw(dfc, "azure.alert.endTimeUtc")).toBe(ev(sid, "airag8").ts);
    expect(t(dfc)).toBeGreaterThan(t(ev(sid, "airag8")));
    expect(Date.parse(String(raw(dfc, "azure.alert.startTimeUtc")))).toBe(t(ev(sid, "airag4")) - Number(raw(ev(sid, "airag4"), "azure.open_ai.duration_ms")));
  });

  it("RAG: the poisoned completions are far larger than the baseline response", () => {
    const base = ev("ai-rag-chatbot-document-injection", "airag1");
    const big = ev("ai-rag-chatbot-document-injection", "airag8");
    const baseLen = Number(raw(base, "azure.open_ai.properties.response_length"));
    const bigLen = Number(raw(big, "azure.open_ai.properties.response_length"));
    expect(bigLen).toBeGreaterThan(baseLen * 5);
  });

  it("KB: the page edited from the risky sign-in is the resource Copilot later cites", () => {
    const signin = ev("ai-stored-injection-copilot-kb", "aikb2");
    const edit = ev("ai-stored-injection-copilot-kb", "aikb3");
    const answer = ev("ai-stored-injection-copilot-kb", "aikb5");
    // same hostile address signs in then edits the page
    expect(signin.src_ip).toBe("198.51.100.66");
    expect(edit.src_ip).toBe("198.51.100.66");
    expect(t(edit)).toBeGreaterThan(t(signin));
    expect(raw(edit, "data.office365.Operation")).toBe("FileModified");
    // the CopilotInteraction record names the edited page as an accessed resource, flags clear
    const resources = raw(answer, "data.office365.CopilotEventData.AccessedResources") as Array<Record<string, unknown>>;
    expect(resources.some(r => r.Name === "Vendor-Payment-Instructions.aspx")).toBe(true);
    expect(resources.every(r => r.XPIADetected === false)).toBe(true);
    const messages = raw(answer, "data.office365.CopilotEventData.Messages") as Array<Record<string, unknown>>;
    expect(messages.find(m => m.isPrompt)?.JailbreakDetected).toBe(false);
    expect(raw(answer, "data.office365.RecordType")).toBe("261");
    expect(t(answer)).toBeGreaterThan(t(edit));
  });

  it("KB: the payment-change email follows the poisoned Copilot answer", () => {
    const answer = ev("ai-stored-injection-copilot-kb", "aikb5");
    const email = ev("ai-stored-injection-copilot-kb", "aikb6");
    expect(email.event_type).toBe("email_sent");
    expect(raw(email, "data.office365.Operation")).toBe("Send");
    expect(raw(email, "email.to.address")).toBe("accounts-payable@nexacorp.com");
    expect(t(email)).toBeGreaterThan(t(answer));
  });
});
