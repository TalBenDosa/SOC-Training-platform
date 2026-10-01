import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { source, kindOf, TRAFFIC_COLUMNS, THREAT_COLUMNS } from "./paloalto";
import { runFirewallSuite, cloneLog, repeatEvent, type EvidenceKey } from "./firewall-testkit";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

/** Parse one PAN CSV body (quotes only around values containing commas / misc). */
function csv(line: string): string[] {
  const out: string[] = []; let cur = "", q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) { if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true; else if (c === ",") { out.push(cur); cur = ""; } else cur += c;
  }
  out.push(cur);
  return out;
}
function parseRaw(line: string): Record<string, string> {
  const body = line.replace(/^<\d+>\w{3} \d+ [\d:]+ \S+ /, "");
  const f = csv(body);
  const cols = f[3] === "TRAFFIC" ? TRAFFIC_COLUMNS : THREAT_COLUMNS;
  expect(f.length).toBe(cols.length);
  const r: Record<string, string> = {};
  f.forEach((v, i) => { if (v !== "" && !cols[i].startsWith("future_use")) r[cols[i]] = v; });
  return r;
}
const panTime = (r: Record<string, unknown>) => Date.parse(String(r.receive_time).replace(/\//g, "-").replace(" ", "T") + "Z");

describe("paloalto: wire format", () => {
  it("card raw lines parse to the card JSON with our column order (117 / 123 columns)", () => {
    const md = readFileSync(join(process.cwd(), "docs", "log-schemas", "fw-paloalto.md"), "utf8");
    const raws = [...md.matchAll(/```text\s*\n([\s\S]*?)```/g)].map(m => m[1].trim());
    const jsons = cardSamples("fw-paloalto.md");
    expect(raws.length).toBe(jsons.length);
    raws.forEach((line, i) => expect(parseRaw(line)).toEqual(jsons[i]));
  });
  it("our rawLine round-trips to the record", () => {
    for (const c of corpusFor(source.schema.telemetrySources)) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (log) expect(parseRaw(log.rawLine!)).toEqual(log.record);
    }
  });
  it("same connection keeps session + NAT values (start/end pair)", () => {
    const ev = corpusFor(["firewall"]).filter(c => c.ev.id.startsWith("evt_efe_0"));
    const [a, b] = ev.map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId))!.record);
    expect(a.sessionid).toBe(b.sessionid);
    expect(a.natsrc).toBe(b.natsrc);
    expect(a.subtype).toBe("start");
    expect(b.subtype).toBe("end");
  });
});

const cardLog = (i: number): NativeLog => {
  const r = cardSamples("fw-paloalto.md")[i] as Record<string, unknown>;
  return { sourceId: "paloalto", kind: String(r.type), format: "csv", record: r, timeMs: panTime(r) };
};

runFirewallSuite({
  source, kindOf,
  crossMin: 0.9,
  cardTime: panTime,
  // Zeek/Corelight NSM records are not firewall logs (intra-segment traffic the firewall never sees).
  nullAllowed: ev => (/zeek|corelight/i.test(ev.vendor ?? "") ? "passive NSM sensor, not a firewall record" : null),
  evidenceExempt: (log): EvidenceKey[] => {
    const ex: EvidenceKey[] = [];
    // PAN TRAFFIC logs carry no FQDN / URL (only `category`); file-subtype THREAT logs put the filename in `misc`.
    if (log.kind === "TRAFFIC" || log.record.subtype === "file") ex.push("network.domain", "network.url");
    // User-ID maps internal users only; an internet-sourced session has no srcuser.
    if (log.record.from === "untrust") ex.push("user");
    return ex;
  },
  fixtures: () => {
    const ctx = makeCtx("nexacorp");
    // "began connecting to edge-cdn-updates.xyz every 60 seconds" → six check-ins.
    const beaconEv = corpusFor(["firewall"]).find(c => c.ev.id === "evt_03_c2")!.ev;
    const beacons = repeatEvent(beaconEv, 6, 60).map(e => source.fromTelemetry(e, ctx)!);
    // Port scan + deny-then-allow built from card sample PAN-3 (inbound RDP probe drop).
    const drop = cardLog(2);
    const scan = Array.from({ length: 12 }, (_, i) => cloneLog(drop, drop.timeMs + i * 2000, { dport: String([21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306][i]) }));
    const allowed = cloneLog(drop, drop.timeMs + 600_000, { subtype: "end", action: "allow", dport: "443", session_end_reason: "tcp-fin" });
    return [...beacons, ...scan, allowed];
  },
});
