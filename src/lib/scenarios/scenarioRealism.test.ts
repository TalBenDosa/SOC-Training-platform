/**
 * Log Realism Standard (docs/LOG-REALISM-STANDARD.md) over every scenario on /scenarios.
 *  - R5: every public address is a documentation address (192.0.2.0/24, 198.51.100.0/24,
 *        203.0.113.0/24), the owner-kept 185.220.101.45, or a well-known service used for
 *        that service (Microsoft, Google, GitHub, Dropbox, MEGA, Backblaze, Zscaler, mail
 *        relays, Qualys ASV).
 *  - R8: severity never separates the verdict: in a scenario with attack and non-attack rows,
 *        some non-attack row is rated at least as high as the lowest attack row.
 *  - R3: one SID per Windows account name inside a scenario.
 *  - R10: no em dash in anything the scenario shows.
 */
import { describe, it, expect } from "vitest";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { buildAlertIndex, effectiveSeverity } from "./eventClass";
import type { ScenarioBundle, TelemetryEvent } from "@/lib/sim/types";

const all = (SCENARIOS as unknown as { slug: string; title: string; summary: string; attack_kind: string; build: () => ScenarioBundle }[])
  .map(sc => ({ sc, b: sc.build() }));

// Well-known services used for that service (R5). Prefixes, matched on the dotted string.
const SERVICE_PREFIXES = [
  "13.107.", "20.50.73.", "20.82.41.", "40.107.", "52.98.", "52.123.",            // Microsoft 365 / Azure
  "142.250.", "209.85.", "34.72.140.",                                           // Google / GCP
  "140.82.", "104.16.92.", "104.18.27.", "151.101.",                              // GitHub, npm, Veeam CDN, Fastly
  "162.125.", "31.216.14", "149.137.", "165.225.",                               // Dropbox, MEGA, Backblaze, Zscaler
  "54.210.17.", "34.201.17.",                                                    // CI runners on AWS
  "54.240.", "149.72.", "168.245.", "170.10.", "198.37.150.", "108.174.", "185.70.4", // mail relays (SES, SendGrid, Mimecast, LinkedIn, Proton)
  "64.39.",                                                                      // Qualys ASV scanner
];
const IP = /(?<![\d.\/A-Za-z_-])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\d|\.\d)/g;
function isAllowed(a: number, b: number, c: number, d: number, s: string): boolean {
  if ([a, b, c, d].some(x => x > 255)) return true;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return true;
  if (a === 127 || a === 0 || a >= 224 || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) return true;
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return true;
  if (s === "185.220.101.45") return true;
  return SERVICE_PREFIXES.some(p => s.startsWith(p));
}
function* strings(o: unknown): Generator<string> {
  if (o == null) return;
  if (typeof o === "string") { yield o; return; }
  if (typeof o === "object") for (const v of Object.values(o as Record<string, unknown>)) yield* strings(v);
}
// A client version ("cisco.asa.client_version": "5.1.2.42") looks like an address and is not one.
const ipFields = (e: TelemetryEvent) => ({
  src: e.src_ip, dst: e.dst_ip, net: e.network, dns: e.dns, desc: e.description, fp: e.fp_explanation,
  raw: Object.fromEntries(Object.entries(e.raw ?? {}).filter(([k]) => !/version/i.test(k))),
});

describe("scenario log realism (R3, R5, R8, R10)", () => {
  it("R5: no real third-party public address outside a well-known service", () => {
    const bad: string[] = [];
    const scan = (where: string, s: string) => {
      for (const m of s.matchAll(IP)) {
        // a version string inside a user agent ("Chrome/124.0.0.0") is not an address
        if (!isAllowed(+m[1], +m[2], +m[3], +m[4], m[0])) bad.push(`${where}: ${m[0]}`);
      }
    };
    for (const { sc, b } of all) {
      for (const e of b.events) for (const s of strings(ipFields(e))) scan(`${sc.slug} ${e.id}`, s);
      // the debrief text cites the same addresses (questions, narrative, IOCs, kill chain)
      for (const s of strings({ br: b.briefing, n: b.narrative, q: b.questions, kc: b.killchain, iocs: b.iocs })) scan(`${sc.slug} debrief`, s);
    }
    expect([...new Set(bad)]).toEqual([]);
  });

  it("R8: severity alone never separates attack rows from the rest", () => {
    const rank = { informational: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;
    const bad: string[] = [];
    for (const { sc, b } of all) {
      if (/false_positive/.test(sc.attack_kind)) continue;
      const idx = buildAlertIndex(b.events);
      const atk: number[] = [], non: number[] = [];
      for (const e of b.events) {
        const isAtk = e.expected_verdict ? ["tp", "escalate"].includes(e.expected_verdict) : (!e.is_baseline && !!e.mitre_technique);
        (isAtk ? atk : non).push(rank[effectiveSeverity(e, idx.has(e.id))]);
      }
      if (atk.length && non.length && Math.min(...atk) > Math.max(...non)) bad.push(`${sc.slug}: lowest attack row ${Math.min(...atk)} > highest other row ${Math.max(...non)}`);
    }
    expect(bad).toEqual([]);
  });

  it("R3: one SID per Windows account name in a scenario", () => {
    const bad: string[] = [];
    for (const { sc, b } of all) {
      const sids = new Map<string, Set<string>>();
      for (const e of b.events) {
        const r = (e.raw ?? {}) as Record<string, unknown>;
        for (const role of ["Target", "Subject"]) {
          const name = r[`winlog.event_data.${role}UserName`], sid = r[`winlog.event_data.${role}UserSid`];
          if (typeof name !== "string" || typeof sid !== "string" || !/^S-1-5-21-/.test(sid)) continue;
          const k = name.replace(/^.*\\/, "").toLowerCase();
          (sids.get(k) ?? sids.set(k, new Set()).get(k)!).add(sid);
        }
      }
      for (const [n, s] of sids) if (s.size > 1) bad.push(`${sc.slug} ${n}: ${[...s].join(" ")}`);
    }
    expect(bad).toEqual([]);
  });

  it("R10: no em dash in anything a scenario shows", () => {
    const bad: string[] = [];
    for (const { sc, b } of all) {
      const shown = { title: sc.title, summary: sc.summary, briefing: b.briefing, narrative: b.narrative, lo: b.learning_objectives,
        q: b.questions, kc: b.killchain, iocs: b.iocs, alerts: b.alerts, events: b.events };
      for (const s of strings(shown)) if (s.includes("—")) bad.push(`${sc.slug}: ${s.slice(0, 80)}`);
    }
    expect(bad).toEqual([]);
  });
});
