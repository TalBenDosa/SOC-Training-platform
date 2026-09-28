/**
 * Event search for the scenario investigation table (team-exercise finding #13,
 * also the root cause of #3 — the Threat-Intel Hunt sweep returned 0 hits).
 *
 * The old filter looked at eight visible columns (hostname, user_email, event
 * type, process name, domain, file path…). An analyst searching for the internal
 * IP 10.20.6.28, the rclone SHA-256, `svc_backup` or `lsass` got nothing, because
 * those values live in the raw vendor block. Every SIEM (Splunk, Sentinel,
 * Wazuh Discover, Falcon Event Search) searches the whole record.
 *
 * Query language (deliberately small — it has to be learnable in a glance):
 *   - bare terms          `lsass rclone`      every term must match (AND), anywhere
 *                                             in the record: field NAMES and VALUES
 *   - quoted phrase       `"R:\stage"`        matched as one term
 *   - field:value         `user:svc_backup`   the value must appear in a field whose
 *                                             name matches (see fieldMatches)
 *   - negation            `-firewall`         `-field:value` too
 * Matching is case-insensitive substring.
 *
 * Pure: flattens the event (top-level fields, nested objects, raw block) into
 * key/value pairs once per event object (WeakMap cache — events are immutable
 * for the page's lifetime), then matches. Unit-tested in logSearch.test.ts.
 */

export interface SearchTerm {
  /** Lower-cased field name, or null for a free-text term. */
  field: string | null;
  /** Lower-cased value to find (substring). */
  value: string;
  negate: boolean;
}

/** Split a query into terms, honouring double quotes. */
export function parseSearchQuery(query: string): SearchTerm[] {
  const terms: SearchTerm[] = [];
  // -? field: ( "quoted" | bare ) | -? "quoted" | -? bare
  const re = /(-)?(?:([A-Za-z_][\w.@-]*):)?(?:"([^"]*)"|(\S+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(query)) !== null) {
    const negate = !!m[1];
    let field = m[2] ? m[2].toLowerCase() : null;
    let value = (m[3] ?? m[4] ?? "").toLowerCase();
    // "http://x" or "C:\path" — a bare token whose "field" is a scheme or a
    // drive letter is a value, not a field query.
    if (field && m[4] !== undefined && (/^[a-z]$/i.test(field) || value.startsWith("//"))) {
      value = `${field}:${value}`;
      field = null;
    }
    if (!value) continue;
    terms.push({ field, value, negate });
  }
  return terms;
}

/** Field name → normalised form used for comparisons: lower-case, alphanumerics only. */
function norm(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/**
 * Aliases: the analyst types the concept, the logs spell it per vendor.
 * Each alias maps to a predicate over the NORMALISED last key segment and the
 * normalised full key.
 */
type KeyPred = (last: string, full: string) => boolean;

const IP_KEY: KeyPred = l => l === "ip" || l.endsWith("ip") || /ip(v)?[46]$/.test(l) || l.endsWith("ipaddress") || l.endsWith("addr") || l.endsWith("address") && !l.includes("mail");
const SRC_KEYS = ["srcip", "sourceip", "clientip", "callerip", "sourceaddress", "src", "ipaddress", "actoripaddress", "clientipaddress", "localaddressip4", "localip", "sourceipaddress", "remotehost"];
const DST_KEYS = ["dstip", "destinationip", "destip", "remoteip", "remoteaddressip4", "dst", "destinationaddress", "serverip", "targetip"];
const isSrc = (k: string) => SRC_KEYS.includes(k) || ((k.startsWith("src") || k.startsWith("source")) && IP_KEY(k, k));
const isDst = (k: string) => DST_KEYS.includes(k) || ((k.startsWith("dst") || k.startsWith("dest") || k.startsWith("remote")) && IP_KEY(k, k));
const USER_KEY: KeyPred = (l, f) => l.includes("user") || l.includes("account") || l === "upn" || l.endsWith("principalname") || l === "email" || f === "sourcename" || l === "actor";
const HOST_KEY: KeyPred = (l, f) => l === "host" || l === "hostname" || l.includes("computername") || l === "computer" || l.endsWith("workstationname") || l === "workstation" || l.endsWith("devicename") || l === "agentname" || f === "hostname" || f.endsWith("hostname");
const HASH_KEY: KeyPred = l => l.includes("sha256") || l.includes("sha1") || l.includes("md5") || l.includes("hash");
const PROC_KEY: KeyPred = l => l.includes("process") || l.includes("image") || l.includes("filename") || l.includes("commandline") || l.includes("cmdline") || l === "name" || l.endsWith("exe");
const CMD_KEY: KeyPred = l => l.includes("commandline") || l.includes("cmdline");
const DOMAIN_KEY: KeyPred = l => l.includes("domain") || l.includes("url") || l.includes("query") || l.includes("servername") || l === "sni" || l.endsWith("fqdn");
const PORT_KEY: KeyPred = l => l.endsWith("port");

const ALIASES: Record<string, KeyPred> = {
  ip: IP_KEY,
  srcip: (l, f) => isSrc(l) || isSrc(f),
  sourceip: (l, f) => SRC_KEYS.includes(l) || SRC_KEYS.includes(f),
  dstip: (l, f) => isDst(l) || isDst(f),
  destip: (l, f) => DST_KEYS.includes(l) || DST_KEYS.includes(f),
  destinationip: (l, f) => DST_KEYS.includes(l) || DST_KEYS.includes(f),
  user: USER_KEY, username: USER_KEY, account: USER_KEY, email: USER_KEY,
  host: HOST_KEY, hostname: HOST_KEY, computer: HOST_KEY, computername: HOST_KEY, agent: HOST_KEY, device: HOST_KEY,
  hash: HASH_KEY, sha256: l => l.includes("sha256"), md5: l => l.includes("md5"), sha1: l => l.includes("sha1"),
  process: PROC_KEY, proc: PROC_KEY, image: PROC_KEY,
  cmd: CMD_KEY, cmdline: CMD_KEY, commandline: CMD_KEY,
  domain: DOMAIN_KEY, url: DOMAIN_KEY,
  port: PORT_KEY,
};

/**
 * Does the flattened key `key` (e.g. "raw.crowdstrike.UserName", "process.name",
 * "dst_ip") answer to the field the analyst typed?
 *  - an alias (user, ip, dst_ip, hash, host, …) → its predicate;
 *  - else the typed name equals the full key, its last segment, or is a
 *    dotted suffix of it ("UserName", "crowdstrike.UserName" both match
 *    "raw.crowdstrike.UserName").
 */
export function fieldMatches(key: string, field: string): boolean {
  const lowerKey = key.toLowerCase();
  const segs = lowerKey.split(".");
  const last = norm(segs[segs.length - 1]);
  const full = norm(lowerKey.replace(/^raw\./, ""));
  const nf = norm(field);
  if (!nf) return false;
  if (full === nf || last === nf) return true;
  const lowerField = field.toLowerCase();
  if (lowerKey === lowerField || lowerKey.endsWith(`.${lowerField}`)) return true;
  const alias = ALIASES[nf];
  return alias ? alias(last, full) : false;
}

export interface FlatEntry { key: string; value: string }

interface Indexed { entries: FlatEntry[]; hay: string }

const cache = new WeakMap<object, Indexed>();

function flattenInto(prefix: string, v: unknown, out: FlatEntry[], depth: number): void {
  if (v === null || v === undefined || depth > 6) return;
  if (Array.isArray(v)) {
    v.forEach(item => flattenInto(prefix, item, out, depth + 1));
    return;
  }
  if (typeof v === "object") {
    for (const [k, child] of Object.entries(v as Record<string, unknown>)) {
      flattenInto(prefix ? `${prefix}.${k}` : k, child, out, depth + 1);
    }
    return;
  }
  out.push({ key: prefix, value: String(v) });
}

/** Every leaf of the event as `key → value` (raw block keys are prefixed "raw."). */
export function flattenEvent(ev: object): FlatEntry[] {
  return indexEvent(ev).entries;
}

function indexEvent(ev: object): Indexed {
  const hit = cache.get(ev);
  if (hit) return hit;
  const entries: FlatEntry[] = [];
  flattenInto("", ev, entries, 0);
  // Keys and values both searchable — "a field names search" (`GrantedAccess`)
  // is how an analyst asks "which events carry this field at all".
  const hay = entries.map(e => `${e.key}\u0001${e.value}`).join("\u0002").toLowerCase();
  const idx = { entries, hay };
  cache.set(ev, idx);
  return idx;
}

function termMatches(idx: Indexed, t: SearchTerm): boolean {
  if (t.field === null) return idx.hay.includes(t.value);
  return idx.entries.some(e => fieldMatches(e.key, t.field!) && e.value.toLowerCase().includes(t.value));
}

/** True when the event satisfies every term of the query. An empty query matches all. */
export function matchesQuery(ev: object, terms: readonly SearchTerm[]): boolean {
  if (terms.length === 0) return true;
  const idx = indexEvent(ev);
  for (const t of terms) {
    const hit = termMatches(idx, t);
    if (t.negate ? hit : !hit) return false;
  }
  return true;
}

/** Convenience: parse + filter. */
export function searchEvents<T extends object>(events: readonly T[], query: string): T[] {
  const terms = parseSearchQuery(query);
  if (terms.length === 0) return events.slice();
  return events.filter(e => matchesQuery(e, terms));
}
