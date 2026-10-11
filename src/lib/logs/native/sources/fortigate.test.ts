import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { source, kindOf, toRawLine } from "./fortigate";
import { runFirewallSuite, cloneLog, repeatEvent, type EvidenceKey } from "./firewall-testkit";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

const fgtTime = (r: Record<string, unknown>) => Number(r.eventtime) / 1e6;
const cardLog = (i: number): NativeLog => {
  const r = cardSamples("fw-fortigate.md")[i] as Record<string, unknown>;
  return { sourceId: "fortigate", kind: kindOf(r)!, format: "kv", record: r, timeMs: fgtTime(r) };
};

describe("fortigate: wire format", () => {
  it("our key=value writer reproduces every card raw line from its JSON (quoting rules)", () => {
    const md = readFileSync(join(process.cwd(), "docs", "log-schemas", "fw-fortigate.md"), "utf8");
    const raws = [...md.matchAll(/```text\s*\n([\s\S]*?)```/g)].map(m => m[1].trim());
    const jsons = cardSamples("fw-fortigate.md") as Record<string, unknown>[];
    expect(raws.length).toBe(jsons.length);
    // eventtime is a 19-digit ns integer: compare everything except its sub-ms digits (JS double precision).
    raws.forEach((line, i) => expect(toRawLine(jsons[i]).replace(/eventtime=\d+/, "")).toBe(line.replace(/eventtime=\d+/, "")));
  });
  it("logid is a quoted 10-digit string and eventtime is epoch ns", () => {
    for (const c of corpusFor(source.schema.telemetrySources)) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      expect(String(log.record.logid)).toMatch(/^\d{10}$/);
      expect(log.rawLine).toMatch(/ logid="\d{10}" /);
      expect(String(log.record.eventtime)).toMatch(/^\d{19}$/);
      expect(Number(log.record.eventtime) / 1e6).toBe(log.timeMs);
    }
  });
});

runFirewallSuite({
  source, kindOf,
  crossMin: 0.9,
  cardTime: fgtTime,
  nullAllowed: ev => (/zeek|corelight/i.test(ev.vendor ?? "") ? "passive NSM sensor, not a firewall record" : null),
  evidenceExempt: (log, ev): EvidenceKey[] => {
    const ex: EvidenceKey[] = [];
    // Forward-traffic logs carry no hostname/url by default (card: UNVERIFIED → not emitted).
    if (log.kind === "traffic/forward") ex.push("network.domain", "network.url");
    // The file hash exists only in utm/virus (infected verdicts); downloads appear as web-filter URLs.
    ex.push("sha256");
    // IPS logs carry hostname + path (not the full URL) and no user (card 3.4).
    if (log.kind === "utm/ips") ex.push("network.url", "user");
    // No destination-host name field in FortiOS logs; UTM logs have no srcname.
    const roleDst = ev.hostname && log.record.devname !== ev.hostname && (log.record.srcintfrole === "wan");
    if (roleDst || (log.kind !== "traffic/forward" && log.record.devname !== ev.hostname)) ex.push("hostname");
    if (log.record.srcintfrole === "wan") ex.push("user");
    return ex;
  },
  fixtures: () => {
    const ctx = makeCtx("rocketstack");
    // "sent HTTPS traffic every 45 seconds to api.telemetry-cdn.net" → six sessions.
    const beaconEv = corpusFor(["firewall"]).find(c => c.ev.id === "evt_sc_04_c2_beacon")!.ev;
    const beacons = repeatEvent(beaconEv, 6, 45).map(e => source.fromTelemetry(e, ctx)!);
    const deny = cardLog(2); // FGT-3 inbound RDP deny
    const scan = Array.from({ length: 12 }, (_, i) => cloneLog(deny, deny.timeMs + i * 2000, { dstport: [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306][i] }));
    const allowed = cloneLog(deny, deny.timeMs + 600_000, { action: "close", dstport: 443, service: "HTTPS" });
    const fail = cardLog(6); // FGT-7 admin login failed
    const brute = Array.from({ length: 6 }, (_, i) => cloneLog(fail, fail.timeMs + i * 30_000, {}));
    return [...beacons, ...scan, allowed, ...brute];
  },
});
