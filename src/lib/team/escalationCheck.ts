/**
 * A Tier-1 escalation must say WHY with evidence from the log (2026-10-18 review: escalations went
 * to Tier-2 with "TI", "Th external IP", "I dont know what this file", "Ran a suspicious code").
 * The rationale needs RATIONALE_MIN_CHARS and must cite a value the log or the picked IOCs carry:
 * a host, user, address, process, command line token, hash, domain or field value.
 */
export const RATIONALE_MIN_CHARS = 25;

const SKIP = new Set(["true", "false", "null", "allowed", "success", "info", "informational", "low", "medium", "high", "critical"]);

/** Values worth citing from a log payload (raw fields included), lower-cased, 4+ chars. */
export function citableValues(payload: Record<string, unknown> | undefined): string[] {
  const out = new Set<string>();
  const walk = (v: unknown, depth: number) => {
    if (depth > 3 || v == null) return;
    if (typeof v === "string" || typeof v === "number") {
      const s = String(v).trim().toLowerCase();
      if (s.length >= 4 && s.length <= 200 && !SKIP.has(s)) {
        out.add(s);
        // a path / command line: its executable and file names count too
        for (const part of s.split(/[\s\\/"'=,;:()]+/)) if (part.length >= 5 && /[a-z]/.test(part)) out.add(part);
      }
      return;
    }
    if (Array.isArray(v)) { v.slice(0, 20).forEach(x => walk(x, depth + 1)); return; }
    if (typeof v === "object") for (const [k, x] of Object.entries(v as Record<string, unknown>)) if (!["description", "id", "tier", "ts", "seq"].includes(k)) walk(x, depth + 1);
  };
  walk(payload, 0);
  return [...out];
}

/** Words that name an IOC by its kind ("the malicious IP", "the sender"), per attached IOC type. */
const KIND_WORDS: Record<string, RegExp> = {
  ip: /\b(ip|ips|address|addresses|ipv4|source|destination)\b/i,
  domain: /\b(domain|domains|url|link|site|website|hostname)\b/i,
  url: /\b(url|link|site|website|domain)\b/i,
  email: /\b(e-?mail|sender|from address|mailbox|recipient)\b/i,
  hash: /\b(hash|sha-?256|sha-?1|md5|file|binary|attachment)\b/i,
  user: /\b(user|account|username|identity)\b/i,
  host: /\b(host|machine|workstation|endpoint|server|device)\b/i,
  process: /\b(process|binary|executable|command)\b/i,
};

export function rationaleProblem(text: string, payload: Record<string, unknown> | undefined, iocs: { value: string; type?: string }[]): string | null {
  const t = text.trim().toLowerCase();
  if (t.length < RATIONALE_MIN_CHARS) return `Say why in at least ${RATIONALE_MIN_CHARS} characters: what in the log is suspicious.`;
  const cites = [...iocs.map(i => i.value.trim().toLowerCase()).filter(v => v.length >= 4), ...citableValues(payload)];
  if (cites.some(v => t.includes(v))) return null;
  // "Because of the malicious IP" with that IP attached as an IOC is evidence: the ticket carries the
  // value and Tier-2 sees exactly which address is meant (trainee report 2026-10-25).
  if (iocs.some(i => KIND_WORDS[String(i.type ?? "").toLowerCase()]?.test(t))) return null;
  const example = iocs[0]?.value ?? citableValues(payload).find(v => /\d|\.|@/.test(v));
  return `Cite the evidence: name the host, user, IP, process, hash or field value from the log that makes it suspicious${example ? ` (for example ${example}), or attach it as an IOC and say what it is` : ""}.`;
}
