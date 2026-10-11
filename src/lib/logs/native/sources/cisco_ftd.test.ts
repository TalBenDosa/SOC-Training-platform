import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { source, kindOf, toRawLine } from "./cisco_ftd";
import { runFirewallSuite, cloneLog, repeatEvent, type EvidenceKey, applianceAdminNull } from "./firewall-testkit";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

const ftdTime = (r: Record<string, unknown>) => Date.parse(String(r.timestamp));
const cardLog = (i: number): NativeLog => {
  const r = cardSamples("fw-cisco.md")[i] as Record<string, unknown>;
  return { sourceId: "cisco_ftd", kind: kindOf(r)!, format: "syslog", record: r, timeMs: ftdTime(r) };
};

describe("cisco_ftd: wire format", () => {
  it("our writer reproduces every FTD card raw line from its JSON", () => {
    const md = readFileSync(join(process.cwd(), "docs", "log-schemas", "fw-cisco.md"), "utf8");
    const raws = [...md.matchAll(/```text\s*\n([\s\S]*?)```/g)].map(m => m[1].trim()).filter(l => l.includes("%FTD-"));
    const jsons = (cardSamples("fw-cisco.md") as Record<string, unknown>[]).filter(j => kindOf(j));
    expect(raws.length).toBe(jsons.length);
    raws.forEach((line, i) => expect(toRawLine(jsons[i])).toBe(line));
  });
  it("blocked connections are 430002 only; ConnectionDuration never on 430002; values are strings", () => {
    for (const c of corpusFor(source.schema.telemetrySources)) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      for (const v of Object.values(log.record)) expect(typeof v).toBe("string");
      if (log.record.AccessControlRuleAction === "Block") expect(log.kind).toBe("430002");
      if (log.kind === "430002") expect(log.record.ConnectionDuration).toBeUndefined();
    }
  });
});

runFirewallSuite({
  source, kindOf,
  crossMin: 0.9,
  cardTime: ftdTime,
  nullAllowed: ev => (/zeek|corelight/i.test(ev.vendor ?? "") ? "passive NSM sensor, not a firewall record" : applianceAdminNull(ev)),
  evidenceExempt: (log, ev): EvidenceKey[] => {
    const ex: EvidenceKey[] = [];
    // FTD security events have no host-name key; only the reporting device (device_id).
    if (log.record.device_id !== ev.hostname) ex.push("hostname");
    if (log.kind !== "430004") ex.push("sha256");
    // 430001 carries no URL key (card §3.2).
    if (log.kind === "430001") ex.push("network.domain", "network.url");
    if (log.record.IngressZone === "OUTSIDE") ex.push("user");
    return ex;
  },
  fixtures: () => {
    const ctx = makeCtx("nexacorp");
    const beaconEv = corpusFor(["firewall"]).find(c => c.ev.id === "evt_03_c2")!.ev;
    const beacons = repeatEvent(beaconEv, 6, 60).map(e => source.fromTelemetry(e, ctx)!);
    const block = cardLog(1); // CISCO-2 inbound RDP block (430002)
    const scan = Array.from({ length: 12 }, (_, i) => cloneLog(block, block.timeMs + i * 2000, { DstPort: String([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306][i]) }));
    const allowed = cloneLog(block, block.timeMs + 600_000, { AccessControlRuleAction: "Allow", AccessControlRuleName: "Allow-DMZ-Web", DstPort: "443" });
    // Card CISCO-4 variant described in the card: the same block raised by Security Intelligence.
    const urlBlock = cardLog(3);
    const siVariant = cloneLog(urlBlock, urlBlock.timeMs, { AccessControlRuleReason: "URL Block", URLSICategory: "Malware" });
    delete siVariant.record.AccessControlRuleName;
    return [...beacons, ...scan, allowed, siVariant];
  },
});
