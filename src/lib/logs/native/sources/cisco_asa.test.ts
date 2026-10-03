import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { source, kindOf, toRawLine } from "./cisco_asa";
import { runFirewallSuite, cloneLog, type EvidenceKey, applianceAdminNull } from "./firewall-testkit";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { extractFacts } from "./firewall-shared";

const asaTime = (r: Record<string, unknown>) => Date.parse(`${r.timestamp} UTC`);
const cardLog = (i: number): NativeLog => {
  const r = (cardSamples("fw-cisco.md") as Record<string, unknown>[]).filter(x => kindOf(x))[i];
  return { sourceId: "cisco_asa", kind: kindOf(r)!, format: "syslog", record: r, timeMs: asaTime(r) };
};

describe("cisco_asa: wire format", () => {
  it("our writer reproduces the ASA card raw lines from their JSON", () => {
    const md = readFileSync(join(process.cwd(), "docs", "log-schemas", "fw-cisco.md"), "utf8");
    const raws = [...md.matchAll(/```text\s*\n([\s\S]*?)```/g)].flatMap(m => m[1].trim().split("\n")).filter(l => l.includes("%ASA-"));
    const jsons = (cardSamples("fw-cisco.md") as Record<string, unknown>[]).filter(j => kindOf(j));
    expect(raws.length).toBe(3);
    raws.forEach((line, i) => expect(toRawLine(jsons[i])).toBe(line));
  });
  it("Message_text follows the Cisco patterns verbatim; no invented keys", () => {
    for (const c of corpusFor(source.schema.telemetrySources)) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      expect(Object.keys(log.record).sort()).toEqual(["Level", "Message_number", "Message_text", "device_id", "timestamp"]);
      const t = String(log.record.Message_text);
      if (log.kind === "106023") expect(t).toMatch(/^Deny (tcp|udp) src \S+:[\d.]+\/\d+ dst \S+:[\d.]+\/\d+ by access-group "\S+" \[0x[0-9a-f]{8}, 0x0\]$/);
      if (log.kind === "302013") expect(t).toMatch(/^Built (inbound|outbound) TCP connection \d+ for \S+:[\d.]+\/\d+ \([\d.]+\/\d+\) to \S+:[\d.]+\/\d+ \([\d.]+\/\d+\)$/);
      if (log.kind === "302014") expect(t).toMatch(/^Teardown TCP connection \d+ for \S+:[\d.]+\/\d+ to \S+:[\d.]+\/\d+ duration \d+:\d\d:\d\d bytes \d+ (TCP FINs|TCP Reset-I|TCP Reset-O|Conn-timeout) from (inside|outside)$/);
    }
  });
});

/** Documented reasons an ASA has no record for an event. */
function asaNull(ev: TelemetryEvent): string | null {
  if (/zeek|corelight/i.test(ev.vendor ?? "")) return "passive NSM sensor, not a firewall record";
  const f = extractFacts(ev, makeCtx("nexacorp"), source.schema.vendorMatch);
  if (!f) return "not a firewall record";
  if (f.blocked && f.cls !== "traffic") return "blocked by an IPS/URL/file engine the ASA does not have";
  if (f.cls === "threat" && f.blocked) return "IPS block";
  if (!f.blocked && f.proto !== "tcp") return "allowed UDP/ICMP (302015/302016 not on the card)";
  return null;
}

runFirewallSuite({
  source, kindOf,
  crossMin: 0.75,
  cardTime: asaTime,
  nullAllowed: ev => asaNull(ev) ?? applianceAdminNull(ev),
  evidenceExempt: (log, ev): EvidenceKey[] => {
    // The ASA body names only sockets: no user, host name, URL, domain or file hash.
    const ex: EvidenceKey[] = ["user", "network.domain", "network.url", "sha256", "dns.query"];
    if (log.record.device_id !== ev.hostname) ex.push("hostname");
    return ex;
  },
  fixtures: () => {
    const deny = cardLog(0); // 106023 inbound RDP deny
    const burst = Array.from({ length: 12 }, (_, i) => cloneLog(deny, deny.timeMs + i * 3000, {
      Message_text: String(deny.record.Message_text).replace("/3389 ", `/${[21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306][i]} `),
    }));
    // An inside host's outbound session to a reverse-shell port (no story carries one today).
    const built = cardLog(1);
    const shell = cloneLog(built, built.timeMs, { Message_text: String(built.record.Message_text).replace(/\/443 /g, "/4444 ") });
    // …and a session it then kept open for hours (teardown duration ≥ 1:00:00).
    const teardown = cardLog(2);
    const longLived = cloneLog(teardown, teardown.timeMs, { Message_text: String(teardown.record.Message_text).replace(/duration \d+:\d\d:\d\d/, "duration 3:12:40") });
    return [...burst, shell, longLived];
  },
});
