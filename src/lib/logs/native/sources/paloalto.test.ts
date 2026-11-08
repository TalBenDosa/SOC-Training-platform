import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { source, kindOf, TRAFFIC_COLUMNS, THREAT_COLUMNS } from "./paloalto";
import { runFirewallSuite, cloneLog, repeatEvent, type EvidenceKey, applianceAdminNull } from "./firewall-testkit";
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
  nullAllowed: ev => (/zeek|corelight/i.test(ev.vendor ?? "") ? "passive NSM sensor, not a firewall record" : applianceAdminNull(ev)),
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

// Sdema review 2026-11-08 (K5): a story's generic brute-force / scan names render as PAN-OS's own
// signatures, and a published server keeps its public VIP in dst with the server in natdst.
describe("paloalto: PAN-OS signatures for generic threats", () => {
  const ctx = makeCtx("nexacorp");
  const base = { id: "pan-sig", ts: "2026-05-10T17:00:51.000Z", source: "firewall" as const, vendor: "Palo Alto Networks PAN-OS", severity: "high" as const };
  it("an RDP brute force is MS-RDP Brute Force Attempt(40021); an SMB one 40004, never the FTP 40001", () => {
    const rdp = source.fromTelemetry({ ...base, event_type: "ids_signature", src_ip: "185.220.101.45", dst_ip: "198.51.100.161", dst_port: 3389,
      raw: { "pan.threat_name": "Brute Force Login Attempt", "pan.threat_category": "brute-force", "pan.app": "ms-rdp", "pan.action": "alert", "pan.natdst": "10.10.20.31" } }, ctx)!;
    expect(rdp.record).toMatchObject({ type: "THREAT", subtype: "vulnerability", threatid: "MS-RDP Brute Force Attempt(40021)", thr_category: "brute-force",
      action: "alert", dst: "198.51.100.161", natdst: "10.10.20.31", natsrc: "0.0.0.0", from: "untrust" });
    const smb = source.fromTelemetry({ ...base, id: "pan-sig-smb", event_type: "ids_blocked", src_ip: "203.0.113.9", dst_ip: "198.51.100.162", dst_port: 445,
      raw: { "pan.threat_id": "40001", "pan.threat_name": "SMB-BruteForce", "pan.action": "block-ip" } }, ctx)!;
    expect(smb.record.threatid).toBe("SMB: User Password Brute-force Attempt(40004)");
  });
  it("a scan is a Zone Protection THREAT/scan: TCP Port Scan(8001) / Host Sweep(8002) / UDP Port Scan(8003), no app, no NAT", () => {
    const mk = (name: string) => source.fromTelemetry({ ...base, id: `scan-${name}`, event_type: "ids_signature", severity: "medium", src_ip: "10.10.20.243", dst_ip: "10.10.20.179", dst_port: 445,
      raw: { "ids.signature_name": name, "ids.signature_id": "SID:40014", "ids.category": "network-scan" } }, ctx)!.record;
    expect(mk("SCAN-TCP-Port-Scan")).toMatchObject({ subtype: "scan", threatid: "TCP Port Scan(8001)", app: "not-applicable", natsrc: "0.0.0.0", natdst: "0.0.0.0", sessionid: "0", thr_category: "scan", proto: "tcp" });
    expect(mk("SCAN-Host-Sweep").threatid).toBe("Host Sweep(8002)");
    expect(mk("SCAN-UDP-Port-Scan")).toMatchObject({ threatid: "UDP Port Scan(8003)", proto: "udp" });
  });
});
