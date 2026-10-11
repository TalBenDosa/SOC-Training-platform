/**
 * Storyline-review batch 6 (AI stories) — the investigability facts each fixed story must keep.
 * docs/qa/storyline-review/batch-6.md lists the defects these guard against.
 */
import { describe, expect, it } from "vitest";
import { AI_FOUNDATION_STORIES } from "./foundation";
import { AI_CORE_STORIES } from "./core";
import { AI_EXTRA_STORIES } from "./extra";
import type { TelemetryEvent } from "@/lib/sim/types";

const ALL = [...AI_FOUNDATION_STORIES, ...AI_CORE_STORIES, ...AI_EXTRA_STORIES];
const story = (id: string) => ALL.find(s => s.id === id)!;
const ev = (sid: string, eid: string): TelemetryEvent => story(sid).events.find(e => e.id === eid)!;
const t = (e: TelemetryEvent) => Date.parse(e.ts);
/** A raw field, as authored or under the UAL emitter's data.office365. prefix. */
const raw = (e: TelemetryEvent, k: string) => {
  const r = e.raw as Record<string, unknown>;
  return r[k] ?? r[`data.office365.${k}`];
};

const IDS = [
  "ai-shadow-chat-upload", "ai-chat-harvest-extension", "ai-svg-invoice-lure", "ai-helpdesk-voice-reset",
  "ai-claude-enterprise-departure", "ai-copilot-oversharing-probe", "ai-claude-shared-secret", "ai-claude-compliance-key-harvest",
];
const CONCLUSION = /\b(malicious|attacker|exfiltrat\w*|c2|compromised|backdoor|disclosed|stolen|ATLAS)\b/i;

describe("AI stories batch 6", () => {
  it.each(IDS)("%s has a real alert row and neutral attack-row descriptions", id => {
    const s = story(id);
    expect(s.events.some(e => e.is_detection)).toBe(true);
    for (const e of s.events) if (!e.is_baseline) expect(e.description ?? "", e.id).not.toMatch(CONCLUSION);
  });

  it("shadow-chat: the bypass after the DLP block is prompt text the PII engine flagged and allowed", () => {
    const block = ev("ai-shadow-chat-upload", "aishd4");
    expect(raw(block, "zscaler.dlpeng")).toBe("PII");
    expect(block.event_type).toBe("http_blocked");
    for (const id of ["aishd6", "aishd7", "aishd8"]) {
      const p = ev("ai-shadow-chat-upload", id);
      expect(t(p)).toBeGreaterThan(t(block));
      expect(raw(p, "zscaler.dlpeng")).toBe("PII");
      expect(p.network?.url ?? raw(p, "zscaler.url") ?? p.description).toBeTruthy();
    }
    // The blocked file and the file on disk share the MD5 the proxy logged.
    expect(block.file?.md5).toBe(ev("ai-shadow-chat-upload", "aishd2").file?.md5);
  });

  it("chat-harvest: the TI alert follows the lookup it matched", () => {
    expect(t(ev("ai-chat-harvest-extension", "aiext10"))).toBeGreaterThan(t(ev("ai-chat-harvest-extension", "aiext4")));
  });

  it("svg lure: the attachment hash is on an EmailAttachmentInfo row of the same message; both copies are purged", () => {
    const att = ev("ai-svg-invoice-lure", "aisvg12");
    expect(raw(att, "category")).toBe("AdvancedHunting-EmailAttachmentInfo");
    expect(raw(att, "data.office365.NetworkMessageId")).toBe(raw(ev("ai-svg-invoice-lure", "aisvg2"), "data.office365.NetworkMessageId"));
    expect(raw(ev("ai-svg-invoice-lure", "aisvg14"), "data.office365.NetworkMessageId")).toBe(raw(ev("ai-svg-invoice-lure", "aisvg3"), "data.office365.NetworkMessageId"));
  });

  it("help desk: the ticket is resolved after the reset and the method wipe; the alert after the sign-in it cites", () => {
    const resolved = t(ev("ai-helpdesk-voice-reset", "aihvr4"));
    expect(resolved).toBeGreaterThan(t(ev("ai-helpdesk-voice-reset", "aihvr5")));
    expect(resolved).toBeGreaterThan(t(ev("ai-helpdesk-voice-reset", "aihvr6")));
    expect(t(ev("ai-helpdesk-voice-reset", "aihvr12"))).toBeGreaterThan(t(ev("ai-helpdesk-voice-reset", "aihvr9")));
  });

  it("departure: one device (managed laptop, Chrome) and the data leaves to removable media", () => {
    const s = story("ai-claude-enterprise-departure");
    for (const e of s.events.filter(e => e.source === "sharepoint")) {
      expect(raw(e, "IsManagedDevice"), e.id).toBe("true");
      expect(raw(e, "BrowserName"), e.id).toBe("Chrome");
    }
    const usb = ev("ai-claude-enterprise-departure", "aicld14");
    expect(raw(usb, "data.office365.Operation")).toBe("FileCopiedToRemovableMedia");
    expect(usb.file?.sha256).toBe(ev("ai-claude-enterprise-departure", "aicld12").file?.sha256);
  });

  it("copilot oversharing: the access grant precedes the reads and the alert follows the download", () => {
    expect(raw(ev("ai-copilot-oversharing-probe", "aicop10"), "TargetUserOrGroupName")).toBe("Everyone except external users");
    expect(t(ev("ai-copilot-oversharing-probe", "aicop10"))).toBeLessThan(t(ev("ai-copilot-oversharing-probe", "aicop3")));
    expect(t(ev("ai-copilot-oversharing-probe", "aicop8"))).toBeGreaterThan(t(ev("ai-copilot-oversharing-probe", "aicop9")));
  });

  it("shared secret: honeytoken alert, then the real key from the same IP, then the key is deactivated", () => {
    const canary = ev("ai-claude-shared-secret", "aicas8");
    const use = ev("ai-claude-shared-secret", "aicas9");
    expect(String(raw(canary, "memo"))).toContain("prod-deploy.env");
    expect(use.src_ip).toBe(canary.src_ip);
    expect(t(use)).toBeGreaterThan(t(canary));
    expect(t(canary)).toBeGreaterThan(t(ev("ai-claude-shared-secret", "aicas7")));
  });

  it("compliance key: push fatigue precedes the session, and the created key's id is the key used later", () => {
    const s = "ai-claude-compliance-key-harvest";
    expect(t(ev(s, "aicak2"))).toBeLessThan(t(ev(s, "aicak1")));
    expect(ev(s, "aicak9").event_type).toBe("mfa_denied");
    expect(raw(ev(s, "aicak5"), "api_key_id")).toBe(raw(ev(s, "aicak6"), "actor.api_key_id"));
  });
});
