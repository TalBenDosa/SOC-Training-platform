import type { Ev } from "@/lib/team/types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildIocTruth, extractIocs, iocDigest, normalizeIoc, type IocTruth, type IocType } from "@/lib/edr/iocIntel";
import { mergeAnswers, publicAnswers } from "@/lib/team/report/serverReport";
import { signState } from "@/lib/logs/ecsFields";

/**
 * Threat-intel truth for a team session's FIRED logs: the public feed rows with the
 * staff-only answers joined back (by inject_id), through the same buildIocTruth the
 * scenario pages use. Server-side only by usage (the answers never leave it; the
 * result is digest-keyed verdicts).
 */
export function buildTeamIocTruth(feedEvents: Ev[], feedInjects: { id: string; channel: string | null; expected_action: unknown }[]): IocTruth {
  const merged = mergeAnswers(feedEvents.filter(e => e.type === "feed.event" && (e.payload as { kind?: unknown }).kind !== "containment_status"), publicAnswers(feedInjects));
  // The team key says "benign" for a story's control / baseline step (a legitimate
  // login before the takeover); buildIocTruth knows that state as is_baseline — without
  // the mapping the step's IOCs inherited the incident's guilt (a clean home IP → malicious).
  const rows = merged.map(e => {
    const p = e.payload as unknown as TelemetryEvent;
    return p.expected_verdict === ("benign" as TelemetryEvent["expected_verdict"]) ? { ...p, is_baseline: true } : p;
  });
  return clearInnocentIocs(buildIocTruth({ events: rows }), rows);
}

// ── 2026-11 review (iocs.md): an IOC is not guilty because it sits in an attack row ──────
// buildIocTruth convicts the IOCs of a story's rows by the incident's key. Three kinds of value
// were convicted that a real analyst (and every other surface) reads as clean:
//  1. the company's own cloud egress: a managed identity's token request (20.50.73.84), or the
//     app's own SDK reading its storage inside the tenant (198.51.100.84);
//  2. a signed OS or runtime binary the attacker abused (powershell.exe, cmd.exe, rundll32.exe,
//     bash, node): blocking its hash would break the machine, so it is clean as a file;
//  3. a signed file that was neither delivered (downloaded, mailed) nor detected: the real app an
//     installer drops (SwiftPDF.exe next to the trojanized SwiftPDF_Setup.exe).
// Unsigned attacker files, delivered files and C2 / attacker addresses keep their verdicts.

const ABUSED_BINARY = /^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|schtasks|svchost|explorer|msiexec|wmic|reg|net1?|sc|curl|conhost|taskhostw|dllhost|winword|excel|outlook|bash|sh|zsh|dash|node|python[0-9.]*|perl|ruby|java|osascript)(\.exe)?$/i;
const DELIVERY_TYPES = new Set(["http_request", "file_download", "email_received", "email_attachment", "proxy"]);
const baseName = (s: unknown) => String(s ?? "").split(/[\\/]/).pop()?.trim() ?? "";
const lc = (s: unknown) => String(s ?? "").trim().toLowerCase();
const rawOf = (e: TelemetryEvent) => (e.raw ?? {}) as Record<string, unknown>;

/** The company's own cloud workload is the source of this row (not an outside caller). */
function ownCloudEgress(e: TelemetryEvent, ip: string): boolean {
  const raw = rawOf(e);
  const src = lc(e.src_ip) === ip || lc(raw["azure.signinlogs.ip_address"]) === ip || lc(raw["CallerIpAddress"]).split(":")[0] === ip || lc(raw["source.ip"]) === ip;
  if (!src) return false;
  const managed = lc((e as { authentication?: { method?: unknown } }).authentication?.method) === "managedidentity"
    || !!raw["azure.signinlogs.managed_identity_type"];
  const ownSdk = !!raw["RequesterTenantId"] && /azure-|azsdk|azure sdk/i.test(String(raw["UserAgentHeader"] ?? ""));
  return managed || ownSdk;
}

interface HashSeen { names: Set<string>; signed: boolean; unsigned: boolean; delivered: boolean; detected: boolean }

export function clearInnocentIocs(truth: IocTruth, rows: TelemetryEvent[]): IocTruth {
  const entries = { ...truth.entries };
  const bad = (d: string) => { const v = entries[d]?.v; return v === "malicious" || v === "suspicious"; };
  const hashes = new Map<string, HashSeen>();
  const ownEgress = new Set<string>();
  for (const e of rows) {
    const raw = rawOf(e);
    for (const ioc of extractIocs(e)) {
      const d = iocDigest(ioc.type, ioc.value);
      if (!bad(d)) continue;
      if (ioc.type === "ip") { if (ownCloudEgress(e, ioc.value)) ownEgress.add(d); continue; }
      if (ioc.type !== "hash") continue;
      const h = hashes.get(d) ?? { names: new Set<string>(), signed: false, unsigned: false, delivered: false, detected: false };
      const isFile = lc(e.file?.sha256) === ioc.value || lc(raw["file.hash.sha256"]) === ioc.value;
      const isProc = lc(e.process?.hash?.sha256) === ioc.value || lc(raw["process.hash.sha256"]) === ioc.value;
      if (isFile) { h.names.add(baseName(e.file?.name || e.file?.path)); const st = signState(raw, "file"); if (st === "trusted") h.signed = true; else if (st) h.unsigned = true; }
      if (isProc) { h.names.add(baseName(e.process?.name || e.process?.path)); const st = signState(raw, "process"); if (st === "trusted") h.signed = true; else if (st) h.unsigned = true; }
      if (isFile && (DELIVERY_TYPES.has(lc(e.event_type)) || !!e.network?.url)) h.delivered = true;
      if ((isFile || isProc) && (e.is_detection === true || /alert|detection/.test(lc(e.event_type)))) h.detected = true;
      hashes.set(d, h);
    }
  }
  for (const d of ownEgress) entries[d] = { ...entries[d], v: "clean", r: undefined };
  for (const [d, h] of hashes) {
    if (h.delivered || h.unsigned) continue;
    const abused = [...h.names].some(n => n && ABUSED_BINARY.test(n));
    if (abused || (h.signed && !h.detected)) entries[d] = { ...entries[d], v: "clean", r: undefined };
  }
  return { ...truth, entries };
}

// ── QA M4: answer only what is asked, only for logs the asker has in hand ──────
// The endpoint used to return the verdict of EVERY IOC of every fired log in one GET —
// with the digest function in the client bundle that was a whole-feed oracle ("which
// of these values are malicious?"). Now the client names the IOCs it wants (≤ 20 per
// call, budgeted per player in the DB) and gets a verdict only for an IOC that appears
// in a log this player has OPENED (or one the team escalated — Tier-2/3 work those from
// the case, not the raw feed). Everything else falls back to what the log itself says.

export const IOC_QUERY_MAX = 20;
const IOC_TYPES = new Set<IocType>(["ip", "domain", "hash"]);
export interface IocQuery { type: IocType; value: string }

/** The request body's `iocs` → normalised, de-duplicated, capped list (invalid entries dropped). */
export function parseIocQuery(body: unknown): IocQuery[] {
  const raw = (body && typeof body === "object" ? (body as { iocs?: unknown }).iocs : null);
  if (!Array.isArray(raw)) return [];
  const out = new Map<string, IocQuery>();
  for (const x of raw) {
    if (out.size >= IOC_QUERY_MAX) break;
    const type = (x as { type?: unknown } | null)?.type, value = (x as { value?: unknown } | null)?.value;
    if (typeof type !== "string" || !IOC_TYPES.has(type as IocType) || typeof value !== "string") continue;
    const v = value.trim().slice(0, 300);
    if (!v) continue;
    const n = normalizeIoc(type as IocType, v);
    if (n) out.set(`${type}:${n}`, { type: type as IocType, value: n });
  }
  return [...out.values()];
}


/** Rows about the hosts of `inHand` (and any extra hosts): the asker's EDR view of those hosts. */
export function rowsOnHosts(events: Ev[], inHand: Ev[], extraHosts: string[] = []): Ev[] {
  const hosts = new Set<string>([...inHand.map(e => lc((e.payload as { hostname?: unknown }).hostname)), ...extraHosts.map(lc)].filter(Boolean));
  if (!hosts.size) return [];
  return events.filter(e => hosts.has(lc((e.payload as { hostname?: unknown }).hostname)));
}
/**
 * The truth entries for `query`, restricted to IOCs that occur in `allowedEvents`
 * (the logs the asker may look up), plus file hashes from `hashEvents` (rows on hosts
 * the asker has in hand). `refused` = asked-for digests not answered.
 */
export function answerIocQuery(truth: IocTruth, query: IocQuery[], allowedEvents: Ev[], hashEvents: Ev[] = []): IocTruth & { refused: string[] } {
  const allowed = new Set<string>();
  for (const e of allowedEvents) for (const ioc of extractIocs(e.payload as unknown as TelemetryEvent)) allowed.add(iocDigest(ioc.type, ioc.value));
  // 2026-11 review: the EDR console shows a host's processes with their hashes. A hash from a
  // row on a host the asker already has in hand reads the same in the console as in the drawer.
  for (const e of hashEvents) for (const ioc of extractIocs(e.payload as unknown as TelemetryEvent)) if (ioc.type === "hash") allowed.add(iocDigest(ioc.type, ioc.value));
  const entries: IocTruth["entries"] = {};
  const refused: string[] = [];
  for (const q of query) {
    const d = iocDigest(q.type, q.value);
    if (!allowed.has(d)) { refused.push(d); continue; }
    const t = truth.entries[d];
    if (t) entries[d] = t;
  }
  return { version: 1, entries, refused };
}
