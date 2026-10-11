/**
 * Wave 3 part C (AI stories) — the investigability facts each story must keep.
 * Modelled on aiStories.batch6.test.ts: a real detection row, neutral attack-row
 * descriptions, and the key chronology / correlation anchors.
 */
import { describe, expect, it } from "vitest";
import { AI_WAVE3_C_STORIES } from "./wave3-c";
import type { TelemetryEvent } from "@/lib/sim/types";

const story = (id: string) => AI_WAVE3_C_STORIES.find(s => s.id === id)!;
const ev = (sid: string, eid: string): TelemetryEvent => story(sid).events.find(e => e.id === eid)!;
const t = (e: TelemetryEvent) => Date.parse(e.ts);
const raw = (e: TelemetryEvent, k: string) => (e.raw as Record<string, unknown>)[k];
// A description must not hand over the analyst's conclusion.
const CONCLUSION = /\b(malicious|attacker|exfiltrat\w*|c2|compromised|backdoor|stolen)\b/i;
// EDR and firewall rows must not name a specific product (those categories get swapped per company).
const PRODUCT = /CrowdStrike|Falcon|SentinelOne|Sophos|Defender for Endpoint|Palo Alto|PAN-OS|FortiGate|Fortinet|Check Point/;

describe("AI wave3-c stories", () => {
  it("both stories are present and sized 8-16 events", () => {
    expect(AI_WAVE3_C_STORIES.map(s => s.id).sort()).toEqual(["ai-malicious-model-pickle", "ai-mcp-tool-poisoning"]);
    for (const s of AI_WAVE3_C_STORIES) {
      expect(s.events.length, s.id).toBeGreaterThanOrEqual(8);
      expect(s.events.length, s.id).toBeLessThanOrEqual(16);
      expect(s.complexity).toBe("advanced");
    }
  });

  it.each(["ai-mcp-tool-poisoning", "ai-malicious-model-pickle"])("%s has a detection and neutral, non-leaking attack rows", id => {
    const s = story(id);
    expect(s.events.some(e => e.is_detection)).toBe(true);
    for (const e of s.events) {
      // Raw telemetry rows must not pre-state the conclusion; a detection row may name its own finding.
      if (!e.is_baseline && !e.is_detection) expect(e.description ?? "", e.id).not.toMatch(CONCLUSION);
      // EDR / firewall rows name no product (they are relabelled to each company's stack).
      if (e.source === "edr" || e.source === "firewall") expect(e.description ?? "", e.id).not.toMatch(PRODUCT);
    }
  });

  it("every event carries its story incident id, and each story is rich in MITRE-tagged rows", () => {
    for (const s of AI_WAVE3_C_STORIES) {
      expect(s.events.every(e => !!e.incident_id)).toBe(true);
      expect(s.events.filter(e => e.mitre_technique).length, s.id).toBeGreaterThanOrEqual(5);
    }
  });

  it("mcp: the key read on the host is the key later abused from a hosting IP, and the key ends EXAMPLE", () => {
    const sid = "ai-mcp-tool-poisoning";
    const KEY = "AKIAZ7QW3MNP5EXAMPLE";
    expect(KEY.endsWith("EXAMPLE")).toBe(true);
    // the credential-read is EDR PROCESS telemetry naming the file (file-read has no native EDR record)
    const read = ev(sid, "aimcp04");
    expect(read.source).toBe("edr");
    expect(read.process?.cmdline).toContain("/.aws/credentials");
    expect(read.mitre_technique).toBe("T1552.001");
    // the same key: baseline from the office, abuse from the hosting IP
    const base = ev(sid, "aimcp00_baseline");
    const abuse = ev(sid, "aimcp06");
    expect(raw(base, "aws.cloudtrail.userIdentity.accessKeyId")).toBe(KEY);
    expect(raw(abuse, "aws.cloudtrail.userIdentity.accessKeyId")).toBe(KEY);
    expect(base.is_baseline).toBe(true);
    expect(abuse.src_ip).toBe("203.0.113.140");
    expect(t(abuse)).toBeGreaterThan(t(read));
    // GetObject bursts and a GuardDuty anomalous-behaviour finding tie to the same key
    expect(raw(ev(sid, "aimcp08"), "aws.cloudtrail.eventName")).toBe("GetObject");
    const gd = ev(sid, "aimcp10");
    expect(gd.is_detection).toBe(true);
    expect(raw(gd, "aws.guardduty.type")).toBe("Exfiltration:S3/AnomalousBehavior");
    // the SOC links the key to the developer host
    const link = ev(sid, "aimcp12");
    expect(link.source).toBe("siem");
    expect(String(raw(link, "ExtendedProperties.Access key"))).toBe(KEY);
    expect(String(raw(link, "ExtendedProperties.Key last read on host"))).toBe("LAP-DEV-12");
  });

  it("pickle: python spawns sh, the connect syscall, then the cron write — in order", () => {
    const sid = "ai-malicious-model-pickle";
    const spawn = ev(sid, "aimp03");
    const connect = ev(sid, "aimp05");
    const cron = ev(sid, "aimp08");
    // auditd records, native field names
    expect(spawn.source).toBe("linux_audit");
    expect(raw(spawn, "data.audit.type")).toBe("EXECVE");
    expect(spawn.process?.parent_name).toBe("python3.11");
    expect(spawn.process?.name).toBe("sh");
    expect(raw(connect, "data.audit.syscall")).toBe("42");          // connect
    expect(connect.event_type).toBe("net_connection");
    expect(raw(cron, "data.audit.type")).toBe("SYSCALL");
    expect(raw(cron, "data.audit.file.name")).toBe("/var/spool/cron/crontabs/m.ben-david");
    expect(cron.mitre_technique).toBe("T1053.003");
    // chronology: download -> spawn -> connect -> cron
    expect(t(ev(sid, "aimp02"))).toBeLessThan(t(spawn));
    expect(t(spawn)).toBeLessThan(t(connect));
    expect(t(connect)).toBeLessThan(t(cron));
    // a detection exists and the firewall + EDR corroborate the callback
    expect(ev(sid, "aimp10").is_detection).toBe(true);
    expect(ev(sid, "aimp06").source).toBe("edr");
    expect(ev(sid, "aimp07").source).toBe("firewall");
  });
});
