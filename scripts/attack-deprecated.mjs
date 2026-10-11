/**
 * ATT&CK technique IDs that must not appear as current IDs in content.
 *
 * LEGACY_GONE: long-retired IDs (pre-v8 renumbering). Never allowed.
 * REVOKED: IDs revoked in a later release, mapped to the ID that replaced them.
 *   v19 (April 2026) split Defense Evasion into Stealth (TA0005) and Defense
 *   Impairment (TA0112) and revoked the T1562 family, T1070.001/.002, T1656 and
 *   T1672. Source: the `revoked-by` relationships in mitre-attack/attack-stix-data
 *   enterprise-attack-19.2.json, cross-checked with the v19 release notes. Full
 *   table: docs/mitre-attack-v19-mapping.md.
 *
 * Teaching text may still name a revoked ID as history ("T1685, formerly
 * T1562.001"), so a REVOKED hit is excused when a legacy marker or the
 * replacement ID sits close by. Structured fields (mitre_technique, answer
 * keys) get no such allowance: use isRevokedId() for those.
 */
export const LEGACY_GONE = ["T1076", "T1086", "T1064", "T1035", "T1117", "T1055.999"];

export const REVOKED = {
  // ATT&CK v19
  "T1562": "T1685",
  "T1562.001": "T1685",
  "T1562.002": "T1685.001",
  "T1562.003": "T1690",
  "T1562.004": "T1686",
  "T1562.006": "T1685",
  "T1562.007": "T1686.001",
  "T1562.008": "T1685.002",
  "T1562.009": "T1688",
  "T1562.010": "T1689",
  "T1562.011": "T1685.003",
  "T1562.012": "T1685.004",
  "T1562.013": "T1686.002",
  "T1070.001": "T1685.005",
  "T1070.002": "T1685.006",
  "T1656": "T1684.001",
  "T1672": "T1684.002",
  // ATT&CK v17
  "T1574.002": "T1574.001",
};

// Kept specific on purpose: a generic "was" or "old" anywhere nearby would
// excuse almost any sentence.
const LEGACY_MARKER = /\b(formerly|previously|legacy|revoked|revocations?|retired|renumbered|became|replaced by|renamed|was T1\d{3}|old (?:id|ids|numbering|sub-technique)|pre-v19|ATT&CK v18|before ATT&CK v19|until ATT&CK v19)\b/i;
const WINDOW = 80;

/** True when `id` is a retired or revoked technique ID (exact match). */
export function isRevokedId(id) {
  return LEGACY_GONE.includes(id) || Object.hasOwn(REVOKED, id);
}

/**
 * Retired/revoked IDs cited in `text` as if current. Returns unique IDs.
 * A bare parent ID (T1562) is matched only when not followed by a sub-technique
 * suffix, so "T1562.008" is reported as T1562.008, not T1562.
 */
export function staleAttackIds(text) {
  const hits = new Set();
  for (const id of LEGACY_GONE) if (text.includes(id)) hits.add(id);
  const re = /\bT1\d{3}(?:\.\d{3})?\b(?![./]\d)/g;
  for (const m of text.matchAll(re)) {
    const id = m[0];
    const next = REVOKED[id];
    if (!next) continue;
    const around = text.slice(Math.max(0, m.index - WINDOW), m.index + id.length + WINDOW);
    if (LEGACY_MARKER.test(around) || around.includes(next)) continue;
    hits.add(id);
  }
  // Reference links: attack.mitre.org/techniques/T1562/001/ is T1562.001. A
  // URL is never history, so no legacy allowance applies.
  for (const m of text.matchAll(/attack\.mitre\.org\/techniques\/(T1\d{3})(?:\/(\d{3}))?/g)) {
    const id = m[2] ? `${m[1]}.${m[2]}` : m[1];
    if (REVOKED[id]) hits.add(id);
  }
  return [...hits];
}
