import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { source, kindOf, toRawLine } from "./checkpoint";
import { runFirewallSuite, cloneLog, repeatEvent, type EvidenceKey } from "./firewall-testkit";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

const cpTime = (r: Record<string, unknown>) => Number(r.time) * 1000;
const cardLog = (i: number): NativeLog => {
  const r = cardSamples("fw-checkpoint.md")[i] as Record<string, unknown>;
  return { sourceId: "checkpoint", kind: kindOf(r)!, format: "syslog", record: r, timeMs: cpTime(r) };
};

describe("checkpoint: wire format", () => {
  it("our Log Exporter writer reproduces every card raw line from its JSON (repeated keys from arrays)", () => {
    const md = readFileSync(join(process.cwd(), "docs", "log-schemas", "fw-checkpoint.md"), "utf8");
    const raws = [...md.matchAll(/```text\s*\n([\s\S]*?)```/g)].map(m => m[1].trim());
    const jsons = cardSamples("fw-checkpoint.md") as Record<string, unknown>[];
    expect(raws.length).toBe(jsons.length);
    raws.forEach((line, i) => expect(toRawLine(jsons[i], cpTime(jsons[i]))).toBe(line));
  });
  it("never mixes the ProductName/ProductFamily variant; values are strings; match-table arrays align", () => {
    for (const c of corpusFor(source.schema.telemetrySources)) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      for (const bad of ["ProductName", "ProductFamily", "svc", "sport_svc", "xlatesport_svc", "app_name", "bytes_out"]) expect(log.record[bad]).toBeUndefined();
      for (const v of Object.values(log.record)) for (const x of Array.isArray(v) ? v : [v]) expect(typeof x).toBe("string");
      if (Array.isArray(log.record.layer_name)) {
        const len = (log.record.layer_name as string[]).length;
        for (const key of ["match_id", "parent_rule", "rule_action", "rule_name", "rule_uid"]) expect((log.record[key] as string[]).length).toBe(len);
      }
    }
  });
});

runFirewallSuite({
  source, kindOf,
  crossMin: 0.9,
  cardTime: cpTime,
  nullAllowed: ev => (/zeek|corelight/i.test(ev.vendor ?? "") ? "passive NSM sensor, not a firewall record" : null),
  evidenceExempt: (log): EvidenceKey[] => {
    const ex: EvidenceKey[] = ["sha256"]; // file hashes belong to Threat Emulation / AV logs (not on this card)
    // Firewall-blade connection logs have no URL/domain field.
    if (log.kind === "firewall") ex.push("network.domain", "network.url");
    // Application Control `resource` carries the host only; Anti-Bot `resource` is the domain.
    if (log.kind === "app_control" || log.kind === "anti_bot") ex.push("network.url");
    // Only the source machine has a name field (src_machine_name); the gateway is in originsicname.
    if (log.record.ifdir === "inbound") ex.push("hostname", "user");
    return ex;
  },
  fixtures: () => {
    const ctx = makeCtx("nexacorp");
    const beaconEv = corpusFor(["firewall"]).find(c => c.ev.id === "evt_03_c2")!.ev;
    const beacons = repeatEvent(beaconEv, 6, 60).map(e => source.fromTelemetry(e, ctx)!);
    const drop = cardLog(1); // CP-2 inbound RDP drop
    const scan = Array.from({ length: 12 }, (_, i) => cloneLog(drop, drop.timeMs + i * 2000, { service: String([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306][i]), service_id: undefined }));
    for (const s of scan) delete s.record.service_id;
    const accepted = cloneLog(drop, drop.timeMs + 600_000, { action: "Accept", rule_action: "Accept", rule_name: "Allow-Web-DMZ", service: "443", service_id: "https" });
    return [...beacons, ...scan, accepted];
  },
});
