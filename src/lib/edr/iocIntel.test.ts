import { describe, it, expect } from "vitest";
import {
  buildIocTruth, assessIoc, hashIntel, ipIntel, domainIntel, extractIocs, iocDigest, normalizeIoc,
  hashVerdictLabel, isSha256Field,
} from "./iocIntel";
import { MALWARE_HASHES } from "@/lib/sim/hashDatabase";
import type { IOC, TelemetryEvent } from "@/lib/sim/types";
import { buildMultiHostIntrusionScenario } from "@/lib/sim/scenario-packs/multiHostIntrusion";
import { buildBackupFalsePositiveScenario } from "@/lib/sim/scenario-packs/backupFalsePositive";

// What the scenario page actually ships to the browser (F-02 projection): no analyst
// description, no MITRE mapping, no expected verdict. The drawer must still be right.
const clientProjection = (events: TelemetryEvent[]): TelemetryEvent[] => events.map(e => {
  const raw: Record<string, unknown> = { ...(e.raw ?? {}) };
  for (const k of Object.keys(raw)) if (/\.description$/i.test(k)) delete raw[k];
  return { ...e, description: undefined, mitre_technique: undefined, mitre_tactic: undefined, expected_verdict: undefined, fp_explanation: undefined, raw };
});

const mhi = buildMultiHostIntrusionScenario();
const truth = buildIocTruth(mhi);
const client = clientProjection(mhi.events);
const maliciousIocs = mhi.iocs.filter(i => i.reputation === "malicious" && ["ip", "domain", "sha256"].includes(i.type));
const typeOf = (t: string) => (t === "sha256" ? "hash" : t === "ip" ? "ip" : "domain") as "hash" | "ip" | "domain";
/** Every client event carrying this IOC value — the surfaces a student can open it from. */
const eventsWith = (type: "hash" | "ip" | "domain", value: string) =>
  client.filter(e => extractIocs(e).some(i => i.type === type && i.value === normalizeIoc(type, value)));

describe("IOC truth — attacker IOCs enrich from the scenario's truth (#2)", () => {
  it("the scenario declares malicious IOCs that actually appear in its logs", () => {
    expect(maliciousIocs.length).toBeGreaterThanOrEqual(4);
    for (const i of maliciousIocs) expect(eventsWith(typeOf(i.type), i.value).length, i.value).toBeGreaterThan(0);
  });

  it("every malicious IOC resolves malicious on every event it appears in — even with descriptions/MITRE stripped", () => {
    for (const i of maliciousIocs) {
      const type = typeOf(i.type);
      for (const ev of eventsWith(type, i.value)) {
        const v = type === "hash" ? hashIntel(i.value, { event: ev, truth }).verdict
          : type === "ip" ? ipIntel(i.value, { event: ev, truth }).verdict
          : domainIntel(i.value, { event: ev, truth }).verdict;
        expect(v, `${i.value} via ${ev.id}`).toBe("malicious");
      }
    }
  });

  it("attacker IPs read as hosting/VPS infrastructure with abuse reports — never 'Comcast residential'", () => {
    for (const i of maliciousIocs.filter(x => x.type === "ip")) {
      const ip = ipIntel(i.value, { event: eventsWith("ip", i.value)[0], truth });
      expect(ip.abusive).toBe(true);
      expect(ip.usageType).toMatch(/Data Center|Hosting/);
      expect(ip.isp).not.toMatch(/Comcast|Telekom|Orange|British Tele/);
      expect(ip.asn).toMatch(/^AS\d+/);
      expect(ip.totalReports).toBeGreaterThan(0);
      expect(ip.confidence).toBeGreaterThanOrEqual(75);
    }
  });

  it("attacker domains are recently registered with vendor detections, anchored before the case date", () => {
    for (const i of maliciousIocs.filter(x => x.type === "domain")) {
      const d = domainIntel(i.value, { event: eventsWith("domain", i.value)[0], truth });
      expect(d.detectionCount).toBeGreaterThan(0);
      expect(d.ageDays).toBeLessThanOrEqual(45);
      expect(d.categories).toContain("Newly Registered Domain");
      // registered BEFORE the scenario used it
      expect(d.creationDate! < mhi.events[mhi.events.length - 1].ts.slice(0, 10)).toBe(true);
    }
  });

  it("a malicious hash is flagged by the host's own EDR engine — no 'Falcon: no detection'", () => {
    for (const i of maliciousIocs.filter(x => x.type === "sha256")) {
      const h = hashIntel(i.value, { event: eventsWith("hash", i.value)[0], truth });
      expect(h.engines.find(e => e.name === "CrowdStrike Falcon")?.detected).toBe(true);
      expect(h.detected).toBeGreaterThanOrEqual(6);
    }
  });

  it("the delivery (lookalike) domain seen only in low-severity telemetry of the attack incident is not clean", () => {
    // the invoice fetch from the lookalike portal (a .docm URL in the attack incident)
    const dl = client.find(e => /\.docm/i.test(e.network?.url ?? "") && !!e.incident_id);
    expect(dl).toBeDefined();
    const dom = extractIocs(dl!).find(i => i.type === "domain")!.value;
    expect(["malicious", "suspicious"]).toContain(domainIntel(dom, { event: dl!, truth }).verdict);
  });

  it("internal addresses are 'internal', not clean public space", () => {
    const internal = client.find(e => e.src_ip?.startsWith("10."))!;
    const ip = ipIntel(internal.src_ip!, { event: internal, truth });
    expect(ip.verdict).toBe("internal");
    expect(ip.abusive).toBe(false);
  });

  it("truth keys are digests — the page source is not a readable list of malicious IOCs", () => {
    const json = JSON.stringify(truth);
    for (const i of maliciousIocs) expect(json.includes(i.value)).toBe(false);
    expect(Object.keys(truth.entries).every(k => /^[0-9a-f]{16}$/.test(k))).toBe(true);
  });
});

describe("IOC enrichment is deterministic — same IOC, same answer everywhere (#2 / #25)", () => {
  it("every surface an IOC appears on returns identical intel", () => {
    for (const i of maliciousIocs) {
      const type = typeOf(i.type);
      const evs = eventsWith(type, i.value);
      const run = (ev: TelemetryEvent) => type === "hash" ? { ...hashIntel(i.value, { event: ev, truth }), fileName: undefined, originalFileName: undefined, malwareName: undefined, fileType: undefined }
        : type === "ip" ? ipIntel(i.value, { event: ev, truth }) : domainIntel(i.value, { event: ev, truth });
      const first = run(evs[0]);
      for (const ev of evs.slice(1)) expect(run(ev), `${i.value} via ${ev.id}`).toEqual(first);
    }
  });

  it("a URL lookup and a domain lookup give the same verdict and the same WHOIS date", () => {
    const url = "https://cdn-sync-eu.net/api/v2/heartbeat";
    const a = domainIntel(url, { truth });
    const b = domainIntel("cdn-sync-eu.net", { truth });
    const c = domainIntel("cdn-sync-eu.net/api/v2/heartbeat", { truth });   // PAN url.full has no scheme
    expect(a.domain).toBe("cdn-sync-eu.net");
    expect(a.lookedUp).toBe(url);
    for (const x of [a, c]) {
      expect(x.verdict).toBe(b.verdict);
      expect(x.creationDate).toBe(b.creationDate);
      expect(x.registrar).toBe(b.registrar);
      expect(x.detectionCount).toBe(b.detectionCount);
    }
  });

  it("the same value always digests the same, case/URL-insensitively", () => {
    expect(iocDigest("domain", "HTTPS://Cdn-Sync-EU.net/x")).toBe(iocDigest("domain", "cdn-sync-eu.net"));
    expect(iocDigest("hash", "AB".repeat(32))).toBe(iocDigest("hash", "ab".repeat(32)));
  });

  it("repeated lookups are stable", () => {
    expect(ipIntel("45.137.101.22", { truth })).toEqual(ipIntel("45.137.101.22", { truth }));
    expect(hashIntel("c".repeat(64))).toEqual(hashIntel("c".repeat(64)));
  });
});

describe("benign-control scenarios stay clean", () => {
  it("a false-positive scenario condemns nothing by association", () => {
    const fp = buildBackupFalsePositiveScenario();
    const t = buildIocTruth(fp);
    expect(Object.values(t.entries).some(e => e.v === "malicious" || e.v === "suspicious")).toBe(false);
    // the signed vendor agent whose behaviour tripped the alert: clean reputation
    const agent = fp.iocs.find(i => i.type === "sha256" && i.reputation === "clean");
    if (agent) expect(hashIntel(agent.value, { truth: t }).verdict).toBe("clean");
  });
});

describe("IOC truth agrees with every scenario's authored reputation table", () => {
  it("malicious/suspicious IOCs never resolve clean; clean ones never resolve malicious", async () => {
    const { SCENARIOS } = await import("@/lib/sim/scenarios");
    const problems: string[] = [];
    for (const s of SCENARIOS as ReadonlyArray<{ slug: string; build: () => { events: TelemetryEvent[]; iocs: IOC[] } }>) {
      const b = s.build();
      const t = buildIocTruth(b);
      for (const i of b.iocs ?? []) {
        if (!["ip", "domain", "url", "sha256"].includes(i.type) || !i.reputation || i.reputation === "unknown") continue;
        const type = i.type === "sha256" ? "hash" : i.type === "ip" ? "ip" : "domain";
        const v = assessIoc(type, i.value, { truth: t }).verdict;
        const dbClean = type === "hash" && assessIoc("hash", i.value).source === "hashdb";
        if ((i.reputation === "malicious" || i.reputation === "suspicious") && (v === "clean") && !dbClean) problems.push(`${s.slug}: ${i.value} authored ${i.reputation} → ${v}`);
        if (i.reputation === "clean" && v === "malicious" && !dbClean) problems.push(`${s.slug}: ${i.value} authored clean → ${v}`);
      }
    }
    expect(problems, problems.join("\n")).toEqual([]);
  });
});

describe("fallbacks without a truth table", () => {
  it("a real MalwareBazaar sample from hashDatabase is malicious wherever it is looked up", () => {
    const h = MALWARE_HASHES[0];
    expect(assessIoc("hash", h.sha256).verdict).toBe("malicious");
    expect(hashIntel(h.sha256).malwareFamily).toBe(h.family);
  });

  it("a live-feed true-positive event's IOCs are malicious (the feed carries expected_verdict)", () => {
    const ev = { id: "x", ts: "2026-09-01T10:00:00Z", source: "firewall", event_type: "net_connection",
      src_ip: "10.1.1.5", dst_ip: "203.0.113.77", expected_verdict: "tp", mitre_tactic: "Command and Control", raw: {} } as TelemetryEvent;
    const ip = ipIntel("203.0.113.77", { event: ev });
    expect(ip.verdict).toBe("malicious");
    expect(ip.categories).toContain("Malware C2");
  });

  it("an unsigned binary the incident flagged reads malicious in the EDR console AND the drawer", () => {
    const sha = "d".repeat(64);
    const ev = { id: "y", ts: "2026-09-01T10:00:00Z", source: "edr", event_type: "process_create", severity: "high",
      process: { pid: 7720, name: "svc.exe", hash: { sha256: sha } }, raw: { "process.code_signature.status": "unsigned" } } as TelemetryEvent;
    expect(hashIntel(sha, { event: ev }).verdict).toBe("malicious");
    expect(hashIntel(sha, { process: { signed: false, flagged: true } }).verdict).toBe("malicious");
    expect(hashVerdictLabel(hashIntel(sha, { process: { signed: false, flagged: true } }))).toMatch(/^Malicious — \d+ \/ 12 engines/);
  });

  it("Check-Hash button recognises the vendor hash fields (incl. Falcon SHA256String)", () => {
    const h = "e".repeat(64);
    for (const k of ["file.hash.sha256", "crowdstrike.SHA256HashData", "crowdstrike.SHA256String", "SHA256", "Hashes"]) expect(isSha256Field(k, h)).toBe(true);
  });
});
