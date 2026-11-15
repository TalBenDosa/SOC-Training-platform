/**
 * VirusTotal: API v3 object reports, native module. No card in docs/log-schemas yet: the shape is the
 * VirusTotal API v3 response for one object (GET /api/v3/ip_addresses/{ip}, /domains/{domain}), as
 * documented at docs.virustotal.com/reference/ip-object and /reference/domains-object:
 *
 *   { "data": { "id": "<ip>", "type": "ip_address", "links": { "self": "<api url>" },
 *               "attributes": { as_owner, asn, country, continent, network, regional_internet_registry,
 *                               reputation, last_analysis_date, last_analysis_stats{...}, tags[], ... } } }
 *
 * A SOAR enrichment step or an analyst pivot stores the response as-is; the per-engine
 * last_analysis_results map (one entry per engine) is trimmed, as every SIEM integration does.
 * Dates are Unix epoch seconds. Input: `source:"threat_intel"` events whose vendor is VirusTotal,
 * with the response flattened under `data.*` raw keys (the registry's virustotal entry).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";

const kind = (): KindSchema => ({
  required: ["data.id", "data.type", "data.links.self", "data.attributes.last_analysis_stats"],
  optional: [],
  openPrefixes: ["data.attributes"],
});

const schema: SourceSchema = {
  sourceId: "virustotal", category: "threat_intel", card: "(none: VirusTotal API v3 object reports)", product: "VirusTotal",
  format: "json", vendorMatch: ["virustotal"], telemetrySources: ["threat_intel"], kinds: { ip_address: kind(), domain: kind() },
};

export function kindOf(record: Record<string, unknown>): string | null {
  const d = record.data as Record<string, unknown> | undefined;
  return d && typeof d === "object" && (d.type === "ip_address" || d.type === "domain") ? d.type : null;
}

/** Unflatten "data.attributes.last_analysis_stats.malicious" style keys into the nested response object. */
function unflatten(raw: Record<string, unknown>, prefix: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (!k.startsWith(prefix)) continue;
    const parts = k.slice(prefix.length).split(".");
    let node = out;
    for (const p of parts.slice(0, -1)) node = (node[p] ??= {}) as Record<string, unknown>;
    node[parts[parts.length - 1]] = v;
  }
  return out;
}

function fromTelemetry(ev: TelemetryEvent, _ctx: NativeCtx): NativeLog | null {
  if (!/virustotal/i.test(ev.vendor ?? "")) return null;
  const raw = (ev.raw ?? {}) as Record<string, unknown>;
  const id = raw["data.id"], type = raw["data.type"];
  if (typeof id !== "string" || (type !== "ip_address" && type !== "domain")) return null;
  const attributes = unflatten(raw, "data.attributes.");
  if (!attributes.last_analysis_stats) return null;
  const path = type === "ip_address" ? "ip_addresses" : "domains";
  const record = {
    data: {
      id, type,
      links: { self: typeof raw["data.links.self"] === "string" ? raw["data.links.self"] : `https://www.virustotal.com/api/v3/${path}/${id}` },
      attributes,
    },
  };
  return { sourceId: "virustotal", kind: type, format: "json", record, timeMs: Date.parse(ev.ts) };
}

const useCases: UseCase[] = [
  {
    id: "virustotal.engines_flag_object", title: "VirusTotal engines flag an address or domain", sourceId: "virustotal", kinds: ["ip_address", "domain"],
    severity: "medium", mitre: [],
    description: "One or more engines rate the object malicious. Treat it as a lead, not a verdict: check how many engines, which ones, and how recent last_analysis_date is. The reverse is the trap: 0 malicious on a freshly rented hosting address proves nothing, it only means nobody has reported it yet.",
    logic: "SOAR: vt_lookup(ip) | where data.attributes.last_analysis_stats.malicious >= 1",
    match: { field: "data.attributes.last_analysis_stats.malicious", op: "gte", value: 1 },
    falsePositives: ["Shared hosting, CDN and VPN-provider addresses flagged for an earlier tenant of the same address"],
  },
  {
    id: "virustotal.hosting_address_clean", title: "Hosting-provider address with no reputation history (context)", sourceId: "virustotal", kinds: ["ip_address"],
    severity: "low", mitre: [],
    description: "Context, not an alert: an address owned by a cloud or VPS provider with zero detections. Attackers rent these by the hour, so a clean score is expected for fresh infrastructure; judge the address by what it did in your own logs (who signed in from it, which app, which device), not by its reputation.",
    logic: "SOAR: vt_lookup(ip) | where data.attributes.last_analysis_stats.malicious == 0 and data.attributes.as_owner matches regex \"(?i)digitalocean|amazon|google|microsoft|ovh|hetzner|linode|vultr|m247\"",
    match: { all: [
      { field: "data.attributes.last_analysis_stats.malicious", op: "eq", value: 0 },
      { field: "data.attributes.as_owner", op: "regex", value: "digitalocean|amazon|google|microsoft|ovh|hetzner|linode|vultr|m247" },
    ] },
    falsePositives: ["Every SaaS and cloud service your own users reach"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
