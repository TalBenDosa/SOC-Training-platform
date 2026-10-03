/**
 * Threat-intel enrichment that agrees with the case the analyst is working.
 *
 * The TI drawer used to decide every verdict from the ONE event it was opened on
 * (a keyword scan of the description, a severity, a couple of vendor fields). On a
 * scenario page the description and MITRE mapping are stripped server-side (F-02),
 * so the scan found nothing and every attacker IOC came back CLEAN — "Comcast
 * residential US", 0/90 — while the Falcon detection next to it said Critical. The
 * same rclone hash was "Malicious" in the EDR console and CLEAN in the drawer, and a
 * domain's WHOIS date changed between the URL lookup and the domain lookup.
 *
 * This module fixes that at the root:
 *
 *  1. TRUTH. `buildIocTruth(bundle)` runs on the SERVER over the full scenario (its
 *     authored `iocs` reputation table + the attack events) and returns a compact map
 *     of IOC → verdict. IOCs seen in the attack incidents enrich as malicious /
 *     suspicious; benign and internal ones as clean / internal. Keys are digests, so
 *     the page source is not a readable list of "the malicious IOCs" — resolving one
 *     requires looking up a value already on screen, which is what the drawer does.
 *
 *  2. DETERMINISM. Every enrichment detail — ASN, registrar, WHOIS age, detection
 *     counts, engine names — is seeded by the IOC VALUE (normalised: a URL resolves
 *     to its hostname), never by the event it was opened from. Same IOC ⇒ same answer
 *     on every surface: scenario log, live feed, EDR console, team consoles.
 *
 *  3. FALLBACK. Without a truth map (live feed, team rooms) the verdict comes from
 *     the event itself — the old vendor-field heuristics plus the event's own
 *     expected_verdict when the surface carries it — still with value-seeded details.
 *
 * Training IOCs are documentation ranges / reserved TLDs; nothing here resolves or
 * contacts anything. It is simulated intel, labelled as such in the UI.
 */
import type { IOC, TelemetryEvent } from "@/lib/sim/types";
import { lookupHash } from "@/lib/sim/hashDatabase";
import { knownGeoForIp } from "@/lib/geo/resolveGeo";

export type IocType = "ip" | "domain" | "hash";
export type IocVerdict = "malicious" | "suspicious" | "clean" | "internal";
export type IocRole =
  | "c2" | "exfil" | "delivery" | "payload" | "tool" | "tor" | "scan"
  | "web-attack" | "blocked" | "dns-tunnel" | "dga" | "pup";

/** One IOC's truth — short keys, it ships to the client. */
export interface IocTruthEntry {
  v: IocVerdict;
  r?: IocRole;
  t?: string;   // first seen in the case, YYYY-MM-DD (anchors WHOIS / first-seen dates)
  g?: string;   // authored country for an IP, when a log carried one
  a?: number;   // authored domain age in days (domain.registration_age_days)
  o?: string;   // PE OriginalFileName of a hash, when any log carried it (the rename tell)
  n?: string;   // on-disk file name of a hash, from the first log that named it
}
export interface IocTruth { version: 1; entries: Record<string, IocTruthEntry> }

const RANK: Record<IocVerdict, number> = { internal: 0, clean: 1, suspicious: 2, malicious: 3 };

// ─── Normalisation, digests, seeded randomness ─────────────────────────────────

/** Hostname of a URL or bare host — tolerant of scheme-less values ("host/path"). */
export function hostnameOf(v: string): string {
  const s = v.trim().toLowerCase();
  if (!s) return s;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//.test(s) ? s : `http://${s}`;
  try {
    const h = new URL(withScheme).hostname;
    if (h) return h.replace(/\.$/, "");
  } catch { /* fall through */ }
  return s.split(/[/?#:]/)[0].replace(/\.$/, "");
}

export function normalizeIoc(type: IocType, value: string): string {
  const v = value.trim();
  if (type === "hash") return v.toLowerCase();
  if (type === "ip") return v;
  return hostnameOf(v);
}

function fnv(s: string, seed: number): number {
  let h = seed >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  return h >>> 0;
}
/** Stable, non-reversible key for an IOC (type-scoped, normalised). */
export function iocDigest(type: IocType, value: string): string {
  const n = `${type}:${normalizeIoc(type, value)}`;
  return fnv(n, 2166136261).toString(16).padStart(8, "0") + fnv(n, 0x9747b28c).toString(16).padStart(8, "0");
}
/** Deterministic [0,1) from a value + a salt index (FNV + murmur3 finaliser, so
 *  neighbouring salts are uncorrelated). */
function rnd(value: string, i: number): number {
  let h = fnv(`${value}#${i}`, 0x811c9dc5);
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b) >>> 0;
  h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return (h >>> 0) / 4294967296;
}
function pickOf<T>(arr: readonly T[], value: string, i: number): T {
  return arr[Math.floor(rnd(value, i) * arr.length) % arr.length];
}
function between(value: string, i: number, lo: number, hi: number): number {
  return lo + Math.floor(rnd(value, i) * (hi - lo + 1));
}

// ─── Field helpers (shared with the log viewers' "Check …" buttons) ────────────

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
export function isInternalIp(ip: string): boolean {
  return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.|255\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip);
}
export function isPublicIp(val: string): boolean {
  return IPV4.test(val) && !isInternalIp(val);
}

const IP_FIELD_KEYS = new Set([
  "source.ip", "destination.ip", "source.nat.ip", "destination.nat.ip", "client.ip", "server.ip",
]);
const DOMAIN_FIELD_KEYS = new Set([
  "dns.question.name", "url.domain", "url.full", "source.domain", "destination.domain",
]);

/**
 * Does this field hold a SHA256 the analyst can run a threat-intel check on?
 * Matches the vendors' real field names — CrowdStrike cs.SHA256HashData, Sysmon
 * Hashes, Defender SHA256 — not only "*.sha256".
 */
export function isSha256Field(key: string, val: string) {
  if (!/^[a-f0-9]{64}$/i.test(val)) return false;
  const k = key.toLowerCase();
  return (
    k === "file.hash.sha256" || k.endsWith(".sha256") || k.endsWith("sha256hashdata") || k.endsWith("sha256string") ||
    k.endsWith("sha256") || k.endsWith(".hashes") || k === "hashes"
  );
}
export function isIpCheckField(key: string, val: string) {
  return IP_FIELD_KEYS.has(key) && isPublicIp(val);
}
export function isDomainCheckField(key: string, val: string) {
  if (!DOMAIN_FIELD_KEYS.has(key)) return false;
  return val.includes(".") && !val.includes(" ") && !isPublicIp(val) && val.length > 3;
}

/** Every IOC-shaped value an event carries (structured fields + vendor raw keys). */
export function extractIocs(e: TelemetryEvent): { type: IocType; value: string }[] {
  const out = new Map<string, { type: IocType; value: string }>();
  const add = (type: IocType, value?: unknown) => {
    if (typeof value !== "string" || !value.trim()) return;
    const n = normalizeIoc(type, value);
    if (!n) return;
    if (type === "ip" && !IPV4.test(n)) return;
    if (type === "domain" && (!n.includes(".") || IPV4.test(n))) return;
    if (type === "hash" && !/^[a-f0-9]{64}$/.test(n)) return;
    out.set(`${type}:${n}`, { type, value: n });
  };
  add("ip", e.src_ip); add("ip", e.dst_ip);
  add("domain", e.network?.domain); add("domain", e.network?.url); add("domain", e.dns?.query);
  add("hash", e.process?.hash?.sha256); add("hash", e.file?.sha256);
  for (const [k, v] of Object.entries(e.raw ?? {})) {
    if (typeof v !== "string") continue;
    if (IP_FIELD_KEYS.has(k)) add("ip", v);
    else if (DOMAIN_FIELD_KEYS.has(k)) add("domain", v);
    else if (isSha256Field(k, v)) add("hash", v);
  }
  return [...out.values()];
}

// ─── Per-event signals ──────────────────────────────────────────────────────────

const OFN_KEYS = ["process.original_file_name", "pe.original_file_name", "OriginalFileName",
  "ProcessVersionInfoOriginalFileName", "crowdstrike.OriginalFilename"];

function rawStr(raw: Record<string, unknown> | undefined, ...keys: string[]): string {
  for (const k of keys) { const v = raw?.[k]; if (typeof v === "string" && v.trim()) return v.trim(); }
  return "";
}

/**
 * True when `hash` is the image hash of this event's own process AND that image is
 * a trusted OS-vendor binary (Microsoft / Apple signed, or living in the system
 * directories). A LOLBin used in an attack — powershell, cmd, rundll32 — is still
 * a clean file: blocking its hash would break Windows, so it must never inherit an
 * incident's guilt by association (review of finding #2, content C1).
 */
function isTrustedSystemImage(e: TelemetryEvent, hash: string): boolean {
  const raw = e.raw;
  const own = [e.process?.hash?.sha256, rawStr(raw, "crowdstrike.SHA256HashData"), rawStr(raw, "process.hash.sha256"),
    rawStr(raw, "SHA256"), rawStr(raw, "InitiatingProcessSHA256")]
    .filter((x): x is string => !!x).map(x => x.toLowerCase());
  if (!own.includes(hash.toLowerCase())) return false;
  const sig = rawStr(raw, "process.code_signature.status", "mde.SignatureStatus").toLowerCase();
  if (/unsigned|invalid|revoked|adhoc/.test(sig)) return false;
  const subject = rawStr(raw, "process.code_signature.subject_name", "mde.Signer");
  const path = (e.process?.path ?? rawStr(raw, "process.executable", "crowdstrike.ImageFileName", "FolderPath")).toLowerCase();
  const vendorSigned = /trusted|valid|signed/.test(sig) && /microsoft|apple/i.test(subject);
  const systemDir = /\\windows\\(system32|syswow64)\\|^\/(usr\/(s?bin|libexec)|bin|sbin|system)\//.test(path);
  return vendorSigned || (systemDir && !sig);
}

const SYSTEM_IMAGE = /\\windows\\(system32|syswow64|winsxs)\\|\\windows\\explorer\.exe$/i;
const LOLBIN = /^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|schtasks|svchost|explorer|msiexec|wmic|reg|net1?|sc|curl|conhost|taskhostw|dllhost)\.exe$/i;
/** Is `hash` this event's own payload (see eventHeuristic)? */
function ownPayloadHashOf(e: TelemetryEvent, hash: string): boolean {
  const authored = authoredHashes(e);
  if (authored.size) return authored.has(hash.toLowerCase()) && !isTrustedSystemImage(e, hash);
  const path = e.process?.path ?? "";
  const name = e.process?.name ?? path.split(/[\\/]/).pop() ?? "";
  return !(SYSTEM_IMAGE.test(path) || LOLBIN.test(name));
}

/** Every sha256 the event itself was authored with (file, process image, raw sha256 fields). */
function authoredHashes(e: TelemetryEvent): Set<string> {
  const out = new Set<string>();
  const add = (v: unknown) => { if (typeof v === "string" && /^[a-f0-9]{64}$/i.test(v.trim())) out.add(v.trim().toLowerCase()); };
  add(e.file?.sha256); add(e.process?.hash?.sha256);
  for (const [k, v] of Object.entries(e.raw ?? {})) if (/sha256/i.test(k)) add(v);
  return out;
}

/** The attack role an event plays, from its MITRE tactic/technique (typed or raw). */
export function roleFromEvent(e: TelemetryEvent): IocRole | undefined {
  const tactic = `${e.mitre_tactic ?? ""} ${rawStr(e.raw, "crowdstrike.Tactic", "threat.tactic.name")}`.toLowerCase();
  const tech = e.mitre_technique ?? rawStr(e.raw, "threat.technique.id");
  if (/exfiltration/.test(tactic) || /^T(1567|1041|1048|1537)/.test(tech)) return "exfil";
  if (/command and control/.test(tactic) || /^T(1071|1573|1090|1095|1102|1219|1572)/.test(tech)) return "c2";
  if (/initial access/.test(tactic) || /^T(1566|1189|1204|1195)/.test(tech)) return "delivery";
  if (/execution|defense evasion|persistence/.test(tactic)) return "payload";
  return undefined;
}

function roleFromTags(tags?: string[]): IocRole | undefined {
  const t = (tags ?? []).join(" ").toLowerCase();
  if (/exfil|outbound-post|cloud-storage/.test(t)) return "exfil";
  if (/c2|beacon|cobalt|mining-pool/.test(t)) return "c2";
  if (/phish|lookalike|delivery|payload-staging|freeware-distribution|trojanized/.test(t)) return "delivery";
  if (/tor/.test(t)) return "tor";
  if (/rclone|remote-access-tool|renamed|psexec|tool/.test(t)) return "tool";
  return undefined;
}

const TP = (e: TelemetryEvent) => e.expected_verdict === "tp" || e.expected_verdict === "escalate";
const HIGH = (e: TelemetryEvent) => e.severity === "high" || e.severity === "critical";

/**
 * What the event ITSELF says about an IOC — the vendor-field heuristics the drawer
 * has always used (malware family / AV verdict / quarantine / Falcon detection
 * block for a hash; TOR / SQLi / scan / C2 / block for an IP; C2 technique or a
 * young registration for a domain), plus the event's expected_verdict when the
 * surface carries one (the live feed does; the scenario page strips it).
 */
export function eventHeuristic(type: IocType, value: string, e: TelemetryEvent): { v: IocVerdict; r?: IocRole } {
  const raw = e.raw ?? {};
  let res: { v: IocVerdict; r?: IocRole } = { v: "clean" };
  if (type === "ip") {
    if (isInternalIp(value)) return { v: "internal" };
    const text = [raw["threat.category"], raw["threat.indicator"], raw["cisco.threat_category"], raw["cp.threat_category"],
      raw["fortinet.threat_category"], raw["pan.threat_category"], raw["ids.category"], raw["okta.risk.reasons"], e.description]
      .filter(Boolean).join(" ").toLowerCase();
    const waf = String(raw["waf.attack.type"] ?? "").toLowerCase();
    const ids = String(raw["ids.category"] ?? "").toLowerCase();
    const act = String(raw["event.action"] ?? "").toLowerCase();
    const blocked = String(raw["session.blocked"] ?? "").toLowerCase() === "true" || act === "block" || act === "deny" ||
      e.event_type === "net_blocked" || e.event_type === "ids_signature";
    if (/\btor\b/.test(text) || String(raw["threat.category"] ?? "").toLowerCase() === "tor") res = { v: "malicious", r: "tor" };
    else if (waf.includes("sql") || /sql|injection/.test(text)) res = { v: "malicious", r: "web-attack" };
    else if (/scan|nmap/.test(ids) || /\bscan|scanner/.test(text)) res = { v: "malicious", r: "scan" };
    else if (/botnet|\bc2\b|malware|cobalt/.test(text)) res = { v: "malicious", r: "c2" };
    else if (blocked) res = { v: "malicious", r: "blocked" };
  } else if (type === "domain") {
    const mitre = e.mitre_technique ?? rawStr(raw, "threat.technique.id");
    const desc = (e.description ?? "").toLowerCase();
    const cat = String(raw["threat.category"] ?? raw["threat.name"] ?? "").toLowerCase();
    const age = Number(raw["domain.registration_age_days"] ?? NaN);
    const c2Tech = ["T1071.001", "T1071.004", "T1568.002", "T1041", "T1048.003"].includes(mitre);
    if (c2Tech || /c2|phish|malware/.test(cat) || /command server|command-and-control|\bc2\b/.test(desc) ||
        (!Number.isNaN(age) && age <= 30) || /registered\s+\d+\s+days?\s+ago/.test(desc)) {
      const r: IocRole = mitre === "T1071.004" || mitre === "T1048.003" ? "dns-tunnel"
        : mitre === "T1568.002" ? "dga" : /phish/.test(cat) ? "delivery" : "c2";
      res = { v: "malicious", r };
    }
  } else {
    // A hash only carries the event's verdict if it is the event's OWN payload: authored
    // on it and not a trusted system image — or, when nothing was authored, an event whose
    // payload is not a Windows binary / LOLBin (a killed powershell.exe is a bad COMMAND,
    // its image stays clean; the parent's and the host's other hashes are not the payload).
    if (!ownPayloadHashOf(e, value)) return { v: "clean" };
    const family = rawStr(raw, "malware.family", "threat.family");
    const name = rawStr(raw, "malware.name", "threat.name", "ThreatName");
    const mtype = rawStr(raw, "malware.type");
    const av = rawStr(raw, "av.verdict");
    // The vendor's own verdict on a file/attachment (Defender for Office 365
    // AttachmentData.FileVerdict, generic file.verdict) — "Malicious" is a detonation result.
    const fileVerdict = rawStr(raw, "data.office365.AttachmentData.FileVerdict", "AttachmentData.FileVerdict", "file.verdict").toLowerCase();
    const quarantine = rawStr(raw, "quarantine.status");
    const result = rawStr(raw, "action_result");
    const vendorDet = rawStr(raw, "crowdstrike.detection.description", "crowdstrike.detection.scenario",
      "crowdstrike.detection.technique", "crowdstrike.Technique");
    const dispo = rawStr(raw, "crowdstrike.detection.pattern_disposition_description", "crowdstrike.PatternDispositionDescription");
    const sig = rawStr(raw, "process.code_signature.status", "file.signature.status", "mde.SignatureStatus").toLowerCase();
    const isPUP = mtype === "PUP" || name.toLowerCase().includes("pup");
    // A behavioural alert + an explicit clean AV reputation and no named family is the
    // textbook false-positive signature (in-house tool) — never read it as malware.
    const cleanRep = av === "clean" && !family && !name;
    const unsignedFlagged = /unsigned|invalid|revoked/.test(sig) && (e.is_detection === true || HIGH(e));
    if (isPUP) res = { v: "suspicious", r: "pup" };
    else if (!cleanRep && (family || name || vendorDet || quarantine === "quarantined" || quarantine === "deleted" ||
        result === "quarantined" || result === "process_killed" || /quarantine|kill process|prevention|block/i.test(dispo) ||
        (av && av !== "clean") || unsignedFlagged || fileVerdict === "malicious")) {
      res = { v: "malicious", r: "payload" };
    }
  }
  // The surface's own ground truth (live feed): a true-positive event's IOCs are bad —
  // for a hash only the event's OWN payload (authored on it, not a trusted system
  // image): the record also shows the parent's / the host's other images (explorer.exe,
  // a signed LOLBin), and those must keep reading clean.
  if (res.v !== "internal" && TP(e) && (type !== "hash" || ownPayloadHashOf(e, value)) && RANK[res.v] < RANK.malicious) {
    res = { v: "malicious", r: res.r ?? roleFromEvent(e) ?? (type === "hash" ? "payload" : undefined) };
  }
  return res;
}

// ─── Truth table (server-side, full scenario) ───────────────────────────────────

// Big shared-infrastructure domains a derived verdict must never condemn — a
// real TI feed reports them clean, and blocking them breaks the business.
const BENIGN_DOMAIN = /(^|\.)(microsoft\.com|microsoftonline\.com|office\.com|office365\.com|outlook\.com|live\.com|windows\.net|windowsupdate\.com|azure\.com|google\.com|googleapis\.com|gstatic\.com|apple\.com|icloud\.com|github\.com|githubusercontent\.com|amazonaws\.com|cloudfront\.net|okta\.com|zoom\.us|slack\.com|salesforce\.com|dropbox\.com|akamaihd\.net)$/;
const INTERNAL_DOMAIN = /\.(local|lan|corp|internal|intranet|home\.arpa)$/;
// Provider ranges the geo map already names (Cloudflare / GitHub / Fastly / AWS /
// GCP / Microsoft) — shared infrastructure, never condemned by association alone.
function isSharedProviderIp(ip: string): boolean {
  const city = knownGeoForIp(ip)?.city ?? "";
  return /\((Cloudflare|GitHub|Fastly|AWS|AWS S3|GCP)\)|Redmond|Seattle/.test(city);
}

/**
 * The scenario's IOC truth table. Precedence:
 *  1. the authored `iocs` reputation (malicious / suspicious / clean) — the answer key;
 *  2. IOCs seen in the scenario's ATTACK incidents — malicious when the event is
 *     attack-grade (a detection, high/critical, a MITRE-mapped or true-positive
 *     event), suspicious when it is supporting telemetry of the same incident
 *     (the lookalike download that preceded the macro, for example);
 *  3. the per-event heuristics for everything else (benign noise stays clean).
 * Internal addresses / the company's own domains are "internal". A benign-control
 * (false-positive) scenario has no malicious IOC and no true-positive event, so
 * nothing is condemned by association.
 */
export function buildIocTruth(bundle: { events: TelemetryEvent[]; iocs?: IOC[] }): IocTruth {
  const events = [...(bundle.events ?? [])].sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? ""));
  const explicit = new Map<string, IocTruthEntry>();
  for (const ioc of bundle.iocs ?? []) {
    const type: IocType | null = ioc.type === "ip" ? "ip" : ioc.type === "domain" || ioc.type === "url" ? "domain"
      : ioc.type === "sha256" ? "hash" : null;
    if (!type || !ioc.value) continue;
    const v: IocVerdict | null = ioc.reputation === "malicious" ? "malicious" : ioc.reputation === "suspicious" ? "suspicious"
      : ioc.reputation === "clean" ? "clean" : null;
    if (!v) continue;
    explicit.set(iocDigest(type, ioc.value), { v, r: roleFromTags(ioc.tags) });
  }
  const explicitBad = new Set([...explicit].filter(([, e]) => RANK[e.v] >= RANK.suspicious).map(([k]) => k));
  const attackScenario = explicitBad.size > 0 || events.some(TP);

  const attackIncidents = new Set<string>();
  if (attackScenario) {
    for (const e of events) {
      if (!e.incident_id || e.expected_verdict === "fp") continue;
      if (TP(e) || (e.is_detection && HIGH(e)) || extractIocs(e).some(i => explicitBad.has(iocDigest(i.type, i.value))))
        attackIncidents.add(e.incident_id);
    }
  }
  const companyDomains = new Set(events
    .flatMap(e => [e.user_email, e.user?.email])
    .filter((m): m is string => !!m && m.includes("@"))
    .map(m => m.split("@")[1].toLowerCase()));
  const isCompanyDomain = (d: string) => INTERNAL_DOMAIN.test(d) || [...companyDomains].some(c => d === c || d.endsWith(`.${c}`));

  const derived = new Map<string, IocTruthEntry>();
  const merge = (key: string, cand: IocTruthEntry) => {
    const cur = derived.get(key);
    if (!cur) { derived.set(key, cand); return; }
    if (RANK[cand.v] > RANK[cur.v]) { cur.v = cand.v; cur.r = cand.r ?? cur.r; }
    else if (!cur.r && cand.r && cand.v === cur.v) cur.r = cand.r;
    cur.g = cur.g ?? cand.g;
    cur.a = cur.a ?? cand.a;
    cur.o = cur.o ?? cand.o;
    cur.n = cur.n ?? cand.n;
  };

  for (const e of events) {
    const benignEvent = e.expected_verdict === "fp" || e.expected_verdict === "informational" || e.is_baseline === true;
    const inAttack = attackScenario && !benignEvent && (e.incident_id ? attackIncidents.has(e.incident_id) : TP(e));
    const attackGrade = TP(e) || e.is_detection === true || HIGH(e) || !!e.mitre_technique || !!rawStr(e.raw, "threat.technique.id");
    const day = (e.ts ?? "").slice(0, 10) || undefined;
    for (const { type, value } of extractIocs(e)) {
      const key = iocDigest(type, value);
      let cand: IocTruthEntry;
      if (type === "ip" && isInternalIp(value)) cand = { v: "internal" };
      else if (type === "domain" && isCompanyDomain(value)) cand = { v: "internal" };
      else if (type === "domain" && BENIGN_DOMAIN.test(value)) cand = { v: "clean" };
      else {
        const h = eventHeuristic(type, value, e);
        cand = { v: h.v, r: h.r };
        const shared = type === "ip" && isSharedProviderIp(value);
        // A file hash only inherits the incident's guilt from an attack-grade event —
        // a benign signed binary that merely appears in low telemetry keeps its own read.
        const trustedImage = type === "hash" && isTrustedSystemImage(e, value);
        if (inAttack && !trustedImage && !(shared && !attackGrade) && (type !== "hash" || attackGrade)) {
          const v: IocVerdict = attackGrade ? "malicious" : "suspicious";
          // A host a file was downloaded from, in an attack incident, is the delivery point.
          const delivered = type !== "hash" && (e.event_type === "http_request" || !!e.network?.url) &&
            (!!e.file || /\.(docm?|xlsm?|pptm|exe|dll|msi|iso|img|zip|rar|7z|js|hta|vbs|lnk|scr)(\?|$)/i.test(e.network?.url ?? "")) ? "delivery" : undefined;
          if (RANK[v] > RANK[cand.v]) cand = { v, r: roleFromEvent(e) ?? h.r ?? delivered ?? (type === "hash" ? "payload" : undefined) };
        }
      }
      if (type === "ip" && value === e.src_ip) {
        const g = e.geo?.country?.trim() || rawStr(e.raw, "source.geo.country_name", "GeoLocation.country_name", "data.srccountry");
        if (g) cand.g = g;
      } else if (type === "ip" && value === e.dst_ip) {
        const g = rawStr(e.raw, "destination.geo.country_name");
        if (g) cand.g = g;
      }
      if (type === "domain") {
        const age = Number(e.raw?.["domain.registration_age_days"] ?? NaN);
        if (!Number.isNaN(age)) cand.a = age;
      }
      if (type === "hash") {
        const ofn = rawStr(e.raw, ...OFN_KEYS);
        if (ofn) cand.o = ofn;
        const fname = value === normalizeIoc("hash", e.process?.hash?.sha256 ?? "") ? e.process?.name
          : value === normalizeIoc("hash", e.file?.sha256 ?? "") ? (e.file?.name ?? e.file?.path.split(/[\\/]/).pop()) : undefined;
        if (fname) cand.n = fname;
      }
      if (!derived.has(key) && day) cand.t = day;
      merge(key, cand);
    }
  }

  const entries: Record<string, IocTruthEntry> = {};
  for (const [k, d] of derived) entries[k] = { ...d };
  for (const [k, x] of explicit) entries[k] = { ...(entries[k] ?? {}), v: x.v, r: x.r ?? entries[k]?.r };
  return { version: 1, entries };
}

// ─── Assessment (verdict for one lookup) ────────────────────────────────────────

export interface IocAssessment {
  verdict: IocVerdict;
  role?: IocRole;
  /** Date the case first saw it (YYYY-MM-DD) — anchors WHOIS / first-seen. */
  refDate: string;
  country?: string;
  ageDays?: number;
  originalFileName?: string;
  fileName?: string;
  source: "hashdb" | "scenario" | "event" | "none";
}

/** Signals the EDR console has for a hash when there is no log event at hand. */
export interface ProcessHint { signed?: boolean; flagged?: boolean }

const DEFAULT_REF = "2026-09-01";

export function assessIoc(
  type: IocType, value: string,
  opts: { event?: TelemetryEvent; truth?: IocTruth | null; process?: ProcessHint } = {},
): IocAssessment {
  const n = normalizeIoc(type, value);
  const evDay = opts.event?.ts?.slice(0, 10);
  if (type === "ip" && isInternalIp(n)) return { verdict: "internal", refDate: evDay || DEFAULT_REF, source: "none" };
  if (type === "hash") {
    const db = lookupHash(n);
    if (db) return { verdict: db.malicious ? "malicious" : "clean", role: db.malicious ? "payload" : undefined, refDate: evDay || DEFAULT_REF, source: "hashdb" };
  }
  const t = opts.truth?.entries[iocDigest(type, n)];
  if (t) return { verdict: t.v, role: t.r, refDate: t.t || evDay || DEFAULT_REF, country: t.g, ageDays: t.a, originalFileName: t.o, fileName: t.n, source: "scenario" };
  if (opts.event) {
    const h = eventHeuristic(type, n, opts.event);
    const age = Number(opts.event.raw?.["domain.registration_age_days"] ?? NaN);
    return { verdict: h.v, role: h.r, refDate: evDay || DEFAULT_REF, ageDays: Number.isNaN(age) ? undefined : age, source: "event" };
  }
  if (type === "hash" && opts.process) {
    // Same rule as the event heuristic: an unsigned binary the case flagged is bad.
    if (opts.process.flagged && opts.process.signed === false) return { verdict: "malicious", role: "payload", refDate: DEFAULT_REF, source: "event" };
  }
  return { verdict: "clean", refDate: evDay || DEFAULT_REF, source: "none" };
}

// ─── Enrichment builders (what the panels render) ───────────────────────────────

function isoMinusDays(day: string, days: number): string {
  const base = Date.parse(`${day}T00:00:00Z`);
  const ms = Number.isNaN(base) ? Date.parse(`${DEFAULT_REF}T00:00:00Z`) : base;
  return new Date(ms - days * 86_400_000).toISOString().slice(0, 10);
}

export interface EngineResult { name: string; detected: boolean; result?: string }

export interface HashIntel {
  hash: string;
  verdict: IocVerdict;
  malicious: boolean;           // verdict is malicious or suspicious
  detected: number;
  total: number;
  malwareName?: string;
  malwareFamily?: string;
  fileType: string;
  fileName?: string;
  originalFileName?: string;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  engines: EngineResult[];
  source: IocAssessment["source"];
}

export const AV_ENGINES = [
  "CrowdStrike Falcon", "Microsoft Defender", "Kaspersky", "Sophos", "ESET-NOD32", "Symantec",
  "Trend Micro", "Bitdefender", "Malwarebytes", "McAfee", "Avast", "SentinelOne",
] as const;

// Known families → the vendor names analysts actually see for them.
const FAMILY_DETECTIONS: Record<string, Partial<Record<(typeof AV_ENGINES)[number], string>>> = {
  CobaltStrike: {
    "CrowdStrike Falcon": "Win/malicious_confidence_100% (W)", "Microsoft Defender": "Backdoor:Win64/CobaltStrike.A!dha",
    "Kaspersky": "Backdoor.Win64.CobaltStrike.gen", "Sophos": "Mal/Cobalt-B", "ESET-NOD32": "Win64/CobaltStrike.A",
    "Symantec": "Backdoor.Cobeacon", "Trend Micro": "TROJ_COBEACON.SM", "Bitdefender": "Gen:Variant.Backdoor.CobaltStrike.1",
  },
  Mimikatz: {
    "CrowdStrike Falcon": "Win/malicious_confidence_100% (W)", "Microsoft Defender": "HackTool:Win32/Mimikatz.A",
    "Kaspersky": "HackTool.Win64.Mimikatz.gen", "Sophos": "HPmal/Mimikatz-A", "ESET-NOD32": "Win64/HackTool.Mimikatz.E",
    "Symantec": "Hacktool.Mimikatz", "Malwarebytes": "HackTool.Mimikatz",
  },
};

// Dual-use tools an operator renames — identified by the PE OriginalFileName.
const TOOL_PROFILES: Record<string, { family: string; label: string; tags: string[] }> = {
  "rclone.exe":   { family: "Rclone (dual-use sync tool)", label: "Rclone", tags: ["rclone", "exfiltration-tool", "dual-use"] },
  "psexec.exe":   { family: "PsExec (Sysinternals)", label: "PsExec", tags: ["psexec", "lateral-movement", "dual-use"] },
  "psexesvc.exe": { family: "PsExec service", label: "PsExec", tags: ["psexec", "lateral-movement", "dual-use"] },
  "anydesk.exe":  { family: "AnyDesk (remote access)", label: "AnyDesk", tags: ["remote-access-tool", "dual-use"] },
  "mimikatz.exe": { family: "Mimikatz", label: "Mimikatz", tags: ["credential-theft", "hacktool"] },
};

function engineName(engine: string, label: string, kind: "malware" | "tool" | "grayware", value: string, i: number): string {
  const n = between(value, 40 + i, 1, 9999);
  if (engine === "CrowdStrike Falcon") return kind === "grayware" ? "Win/grayware_confidence_70% (W)" : `Win/malicious_confidence_${between(value, 60, 90, 100)}% (W)`;
  const T = kind === "tool" ? "HackTool" : kind === "grayware" ? "PUA" : "Trojan";
  switch (engine) {
    case "Microsoft Defender": return `${T}:Win64/${label}.${String.fromCharCode(65 + (n % 6))}!MTB`;
    case "Kaspersky": return kind === "tool" ? `not-a-virus:HEUR:RiskTool.Win64.${label}.gen` : `HEUR:${T}.Win64.${label}.gen`;
    case "Sophos": return kind === "tool" ? `${label} (PUA)` : `Mal/Generic-S`;
    case "ESET-NOD32": return `Win64/${kind === "tool" ? "RiskWare" : "Agent"}.${label}.${String.fromCharCode(65 + (n % 20))}`;
    case "Symantec": return kind === "tool" ? "Hacktool" : "Trojan.Gen.MBT";
    case "Trend Micro": return kind === "tool" ? "HKTL_" + label.toUpperCase().slice(0, 8) : "TROJ_GEN.R002C0DH" + (n % 90 + 10);
    case "Bitdefender": return `Gen:Variant.${kind === "tool" ? "Application" : "Trojan"}.${label}.${n}`;
    case "Malwarebytes": return kind === "tool" ? `RiskWare.${label}` : "Malware.AI." + (n * 7919);
    case "McAfee": return kind === "tool" ? `RDN/${label}` : "Artemis!" + value.slice(0, 12).toUpperCase();
    case "Avast": return `Win64:${kind === "tool" ? "Malware-gen" : "Trojan-gen"}`;
    default: return `${T}.Generic.${n}`;
  }
}

export function hashIntel(
  value: string,
  opts: { event?: TelemetryEvent; truth?: IocTruth | null; process?: ProcessHint } = {},
): HashIntel {
  const hash = normalizeIoc("hash", value);
  const a = assessIoc("hash", hash, opts);
  const raw = opts.event?.raw ?? {};
  const db = lookupHash(hash);
  const ofn = rawStr(raw, ...OFN_KEYS) || a.originalFileName || "";
  const fileName = a.fileName || rawStr(raw, "file.name") || opts.event?.file?.name || opts.event?.process?.name ||
    (opts.event?.file?.path ? opts.event.file.path.split(/[\\/]/).pop() : "") || "";
  const tool = TOOL_PROFILES[(ofn || fileName).toLowerCase()];
  const family = db?.malicious ? db.family : rawStr(raw, "malware.family", "threat.family") || tool?.family || "";
  const name = db?.malicious ? db.name : rawStr(raw, "malware.name", "threat.name", "ThreatName");
  const isBad = a.verdict === "malicious" || a.verdict === "suspicious";

  const famKey = Object.keys(FAMILY_DETECTIONS).find(f => family.toLowerCase().includes(f.toLowerCase()));
  const kind: "malware" | "tool" | "grayware" = a.verdict === "suspicious" ? "grayware" : tool ? "tool" : "malware";
  const label = tool?.label ?? (famKey || (family ? family.replace(/[^A-Za-z0-9]/g, "").slice(0, 14) : "Agent")) ?? "Agent";
  const engines: EngineResult[] = AV_ENGINES.map((eng, i) => {
    if (!isBad) return { name: eng, detected: false };
    // The EDR on the host and the platform AV always agree with a malicious verdict —
    // a lookup never says "Falcon: no detection" for the binary Falcon just flagged.
    const always = eng === "CrowdStrike Falcon" || (a.verdict === "malicious" && eng === "Microsoft Defender");
    const threshold = a.verdict === "malicious" ? 0.78 : 0.12;
    if (!always && rnd(hash, 100 + i) >= threshold) return { name: eng, detected: false };
    const specific = famKey && a.verdict === "malicious" ? FAMILY_DETECTIONS[famKey][eng] : undefined;
    return { name: eng, detected: true, result: specific ?? engineName(eng, label, kind, hash, i) };
  });
  const detected = engines.filter(e => e.detected).length;

  const tags = !isBad ? []
    : db?.malicious ? db.tags
    : tool ? [...tool.tags, ...(ofn && fileName && ofn.toLowerCase() !== fileName.toLowerCase() ? ["renamed-binary"] : [])]
    : a.role === "pup" ? ["pup", "unwanted"]
    : a.role === "exfil" ? ["exfiltration", "trojan"]
    : a.role === "c2" ? ["c2", "beacon"]
    : ["trojan", "malware"];

  const firstSeen = db?.malicious ? `${db.first_seen}`.slice(0, 10)
    : isBad ? isoMinusDays(a.refDate, between(hash, 7, 1, 21))
    : isoMinusDays(a.refDate, between(hash, 8, 400, 2400));
  return {
    hash, verdict: a.verdict, malicious: isBad, detected, total: engines.length,
    malwareName: isBad ? (name || undefined) : undefined,
    malwareFamily: isBad ? (family || (a.role === "pup" ? "PUP.Generic" : undefined)) : undefined,
    fileType: /\.dll$/i.test(fileName) ? "Win32 DLL" : /\.(docm|doc|xlsm|xls)$/i.test(fileName) ? "MS Office document" : "Win32 EXE",
    fileName: fileName || undefined,
    originalFileName: ofn || undefined,
    firstSeen, lastSeen: a.refDate, tags, engines, source: a.source,
  };
}

export interface IpIntel {
  ip: string;
  verdict: IocVerdict;
  abusive: boolean;             // malicious or suspicious
  confidence: number;
  country?: string;
  asn?: string;
  isp?: string;
  usageType?: string;
  totalReports: number;
  lastReported?: string;
  categories: string[];
  source: IocAssessment["source"];
}

// Hosting / VPS networks — where attacker infrastructure actually lives.
const HOSTING = [
  { asn: "AS9009",   isp: "M247 Europe SRL",               country: "Romania" },
  { asn: "AS14061",  isp: "DigitalOcean, LLC",             country: "Netherlands" },
  { asn: "AS24940",  isp: "Hetzner Online GmbH",           country: "Germany" },
  { asn: "AS16276",  isp: "OVH SAS",                       country: "France" },
  { asn: "AS20473",  isp: "The Constant Company, LLC (Vultr)", country: "United States" },
  { asn: "AS60068",  isp: "Datacamp Limited",              country: "United Kingdom" },
  { asn: "AS49981",  isp: "WorldStream B.V.",              country: "Netherlands" },
  { asn: "AS200019", isp: "AlexHost SRL",                  country: "Moldova" },
] as const;
const ACCESS = [
  { asn: "AS7922",  isp: "Comcast Cable Communications, LLC", usage: "Residential / ISP", country: "United States" },
  { asn: "AS3320",  isp: "Deutsche Telekom AG",              usage: "Residential / ISP", country: "Germany" },
  { asn: "AS2856",  isp: "British Telecommunications PLC",   usage: "Business / ISP",    country: "United Kingdom" },
  { asn: "AS3215",  isp: "Orange S.A.",                      usage: "Business / ISP",    country: "France" },
] as const;

export function ipIntel(value: string, opts: { event?: TelemetryEvent; truth?: IocTruth | null } = {}): IpIntel {
  const ip = normalizeIoc("ip", value);
  const a = assessIoc("ip", ip, opts);
  if (a.verdict === "internal") {
    return { ip, verdict: "internal", abusive: false, confidence: 0, country: "—", isp: "Internal network (RFC 1918)",
      usageType: "Private address space — corporate LAN", totalReports: 0, categories: [], source: a.source };
  }
  const ev = opts.event;
  const geoCountry = a.country
    || (ev && ip === ev.src_ip ? (ev.geo?.country?.trim() || rawStr(ev.raw, "source.geo.country_name", "GeoLocation.country_name", "data.srccountry")) : "")
    || (ev && ip === ev.dst_ip ? rawStr(ev.raw, "destination.geo.country_name") : "")
    || knownGeoForIp(ip)?.country || "";
  const bad = a.verdict === "malicious" || a.verdict === "suspicious";
  if (!bad) {
    const pool = geoCountry ? ACCESS.filter(x => x.country === geoCountry) : [];
    const net = pickOf(pool.length ? pool : ACCESS, ip, 1);
    return { ip, verdict: "clean", abusive: false, confidence: 0, country: geoCountry || net.country,
      asn: net.asn, isp: net.isp, usageType: net.usage, totalReports: 0, categories: [], source: a.source };
  }
  if (a.role === "tor") {
    return { ip, verdict: a.verdict, abusive: true, confidence: 100, country: geoCountry || "Germany", isp: "Tor exit relay",
      usageType: "Anonymous Proxy / TOR Exit Node", totalReports: between(ip, 2, 1500, 2400), lastReported: a.refDate,
      categories: ["Anonymous Proxy", "TOR Exit Node", "Hacking"], source: a.source };
  }
  const pool = geoCountry ? HOSTING.filter(h => h.country === geoCountry) : [];
  const net = pickOf(pool.length ? pool : HOSTING, ip, 3);
  const malicious = a.verdict === "malicious";
  const categories: string[] =
    a.role === "c2" ? ["Malware C2", "Hacking"]
    : a.role === "exfil" ? ["Data Exfiltration", "Hosting / VPS abuse"]
    : a.role === "delivery" ? ["Phishing", "Malware Distribution"]
    : a.role === "web-attack" ? ["SQL Injection", "Web App Attack", "Hacking"]
    : a.role === "scan" ? ["Port Scan", "Hacking"]
    : a.role === "blocked" ? ["Brute-Force", "Hacking"]
    : malicious ? ["Malicious Activity", "Hacking"] : ["Suspicious Activity"];
  return {
    ip, verdict: a.verdict, abusive: true,
    confidence: malicious ? between(ip, 4, 78, 100) : between(ip, 4, 25, 55),
    country: geoCountry || net.country, asn: net.asn, isp: net.isp,
    usageType: "Data Center / Web Hosting / Transit",
    totalReports: malicious ? between(ip, 5, 45, 1400) : between(ip, 5, 2, 30),
    lastReported: a.refDate, categories, source: a.source,
  };
}

export interface DomainIntel {
  domain: string;
  /** The value the lookup was opened on, when it was a URL rather than a bare host. */
  lookedUp?: string;
  verdict: IocVerdict;
  malicious: boolean;           // malicious or suspicious
  detectionCount: number;
  total: number;
  registrar?: string;
  creationDate?: string;
  ageDays: number;
  categories: string[];
  tags: string[];
  source: IocAssessment["source"];
}

const BAD_REGISTRARS = ["NameCheap, Inc.", "PDR Ltd. d/b/a PublicDomainRegistry.com", "NICENIC INTERNATIONAL GROUP CO., LIMITED", "Porkbun LLC", "Hostinger Operations, UAB"];
const GOOD_REGISTRARS = ["MarkMonitor Inc.", "CSC Corporate Domains, Inc.", "GoDaddy.com, LLC", "Network Solutions, LLC"];

export function domainIntel(value: string, opts: { event?: TelemetryEvent; truth?: IocTruth | null } = {}): DomainIntel {
  const domain = normalizeIoc("domain", value);
  const a = assessIoc("domain", domain, opts);
  const lookedUp = value.trim().toLowerCase() !== domain ? value.trim() : undefined;
  const bad = a.verdict === "malicious" || a.verdict === "suspicious";
  const ageDays = a.ageDays
    ?? (a.verdict === "malicious" ? between(domain, 1, 3, 40)
      : a.verdict === "suspicious" ? between(domain, 1, 20, 120)
      : between(domain, 1, 1500, 6500));
  const categories: string[] = !bad ? []
    : a.role === "c2" ? ["Command & Control", "Malware C2"]
    : a.role === "exfil" ? ["Data Exfiltration", "Online Storage (unsanctioned)"]
    : a.role === "delivery" ? ["Phishing", "Malware Distribution", "Lookalike Domain"]
    : a.role === "dns-tunnel" ? ["DNS Tunneling", "Data Exfiltration"]
    : a.role === "dga" ? ["Domain Generation Algorithm", "Malware C2"]
    : a.verdict === "malicious" ? ["Malicious", "Suspicious Activity"] : ["Suspicious", "Uncategorized"];
  if (bad && ageDays <= 45) categories.push("Newly Registered Domain"); // same window the truth uses for attacker domains
  const detectionCount = a.verdict === "malicious" ? between(domain, 2, 9, 21) : a.verdict === "suspicious" ? between(domain, 2, 1, 4) : 0;
  const tags = !bad ? [] : [
    ...(a.role === "c2" ? ["c2"] : a.role === "exfil" ? ["exfil"] : a.role === "delivery" ? ["phishing"] : []),
    ...(ageDays <= 30 ? ["recently-registered"] : []),
    "privacy-protected-whois",
  ];
  return {
    domain, lookedUp, verdict: a.verdict, malicious: bad, detectionCount, total: 90,
    registrar: a.verdict === "internal" ? "Corporate (internal zone)" : bad ? pickOf(BAD_REGISTRARS, domain, 3) : pickOf(GOOD_REGISTRARS, domain, 3),
    creationDate: isoMinusDays(a.refDate, ageDays), ageDays, categories, tags, source: a.source,
  };
}

/** One-line summary for compact surfaces (the EDR console's "Look up hash"). */
export function hashVerdictLabel(h: HashIntel): string {
  if (h.verdict === "malicious") {
    const falcon = h.engines.find(e => e.name === "CrowdStrike Falcon" && e.detected)?.result;
    return `Malicious — ${h.detected} / ${h.total} engines${h.malwareFamily ? ` · ${h.malwareFamily}` : ""}${falcon ? ` · Falcon: ${falcon}` : ""}`;
  }
  if (h.verdict === "suspicious") return `Suspicious — ${h.detected} / ${h.total} engines (grayware / dual-use)`;
  return `Clean — 0 / ${h.total} engines`;
}
