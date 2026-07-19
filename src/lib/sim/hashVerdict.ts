/**
 * Threat-intel verdict for a file hash.
 *
 * Scenario hashes are synthetic — they are not real samples, so a real feed
 * lookup would return nothing and every "Check Hash" in a scenario would come
 * back clean, including the dropper the whole story is about. The scenario
 * itself already declares the answer: its `iocs` list marks which hashes are
 * malicious and why. That list is therefore the authority, and the resolution
 * order is:
 *
 *   1. the scenario's own IOC list   (story truth — always wins)
 *   2. the real public-intel hash DB (WannaCry, Mimikatz, … — genuinely known)
 *   3. otherwise: not in any feed    (clean, and that is a real answer too)
 *
 * Detection counts for scenario IOCs are derived deterministically from the
 * hash so the panel shows the same numbers every render — a ratio that changed
 * on re-open would teach students that threat intel is arbitrary.
 */

import type { IOC } from "./types";
import { lookupHash } from "./hashDatabase";

export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";

export interface HashVerdict {
  hash: string;
  verdict: Verdict;
  name: string;
  family?: string;
  detections: number;
  total: number;
  firstSeen?: string;
  source: string;
  tags: string[];
  /** Why this verdict — shown to the analyst so the answer is explainable. */
  rationale: string;
}

const VT_TOTAL = 72;

/** Stable pseudo-value in [0,1) derived from the hash text. */
function seed(hash: string): number {
  let h = 0;
  for (let i = 0; i < hash.length; i++) {
    h = (h * 31 + hash.charCodeAt(i)) >>> 0;
  }
  return (h % 10_000) / 10_000;
}

/** Known product/tool names keep their real casing — "microsoft" reads wrong. */
const TAG_CASING: Record<string, string> = {
  microsoft: "Microsoft", dll: "DLL", exe: "EXE", c2: "C2",
  imds: "IMDS", aws: "AWS", mssql: "MSSQL", oauth: "OAuth", pii: "PII",
};

function titleFromTags(tags: string[], fallback: string): string {
  if (tags.length === 0) return fallback;
  const words = tags[0].replace(/[-_]/g, " ").split(" ").filter(Boolean);
  return words
    .map((w, i) => TAG_CASING[w] ?? (i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(" ");
}

export function resolveHashVerdict(hash: string, iocs: IOC[] = []): HashVerdict {
  const normalized = hash.trim().toLowerCase();

  // ── 1. Scenario IOC list — the story's own answer ────────────────────────
  const ioc = iocs.find(
    i => (i.type === "sha256" || i.type === "md5") && i.value.trim().toLowerCase() === normalized,
  );
  if (ioc) {
    const tags = ioc.tags ?? [];
    const rep = ioc.reputation ?? "unknown";
    const s = seed(normalized);

    if (rep === "malicious") {
      const detections = 44 + Math.floor(s * 24); // 44–67 of 72
      return {
        hash, verdict: "malicious",
        name: titleFromTags(tags, "Malicious file"),
        family: tags.find(t => !["dropper", "stage1", "stage2", "payload"].includes(t)),
        detections, total: VT_TOTAL,
        firstSeen: ioc.first_seen,
        source: "Correlated threat intel — matches an indicator from this incident",
        tags,
        rationale:
          "This hash matches a confirmed indicator in the current investigation. " +
          "Multiple engines flag it and it is tied to the observed attack chain.",
      };
    }
    if (rep === "suspicious") {
      const detections = 4 + Math.floor(s * 12); // 4–15 of 72
      return {
        hash, verdict: "suspicious",
        name: titleFromTags(tags, "Suspicious file"),
        detections, total: VT_TOTAL,
        firstSeen: ioc.first_seen,
        source: "Correlated threat intel — low-confidence detections",
        tags,
        rationale:
          "A minority of engines flag this file, and several of those are generic " +
          "heuristics. Low detection counts are frequently false positives — " +
          "corroborate with process lineage and behaviour before calling it.",
      };
    }
    // Explicitly marked clean/unknown in the scenario.
    return {
      hash, verdict: rep === "clean" ? "clean" : "unknown",
      name: titleFromTags(tags, "Known file"),
      detections: 0, total: VT_TOTAL,
      source: "Correlated threat intel",
      tags,
      rationale:
        rep === "clean"
          ? "No engine flags this file. It appears in the incident as legitimate " +
            "activity — a reminder that not every artefact in a timeline is hostile."
          : "No reputation data. Absence of a verdict is not a verdict; judge this " +
            "one on behaviour.",
    };
  }

  // ── 2. Real public threat intel ──────────────────────────────────────────
  const known = lookupHash(normalized);
  if (known) {
    if (known.malicious) {
      return {
        hash, verdict: "malicious",
        name: known.name,
        family: known.family,
        detections: known.vt_detections, total: known.vt_total,
        firstSeen: known.first_seen,
        source: known.source,
        tags: known.tags,
        rationale:
          `Documented ${known.family} sample. This is a real, publicly catalogued hash — ` +
          `you can verify it yourself on VirusTotal.`,
      };
    }
    return {
      hash, verdict: "clean",
      name: known.name,
      detections: 0, total: known.vt_total,
      source: "Known-good software catalogue",
      tags: [],
      rationale: `${known.description} No engine flags this file.`,
    };
  }

  // ── 3. Not in any feed ───────────────────────────────────────────────────
  return {
    hash, verdict: "clean",
    name: "Not found in threat intel",
    detections: 0, total: VT_TOTAL,
    source: "No feed match",
    tags: [],
    rationale:
      "No engine flags this hash and it appears in no feed. That is meaningful but " +
      "not conclusive — a freshly compiled or targeted payload has no reputation yet. " +
      "Unknown is not the same as safe: fall back to behaviour and process lineage.",
  };
}

export function verdictColor(v: Verdict): string {
  switch (v) {
    case "malicious":  return "text-severity-critical";
    case "suspicious": return "text-severity-medium";
    case "clean":      return "text-neon-green";
    default:           return "text-slate-400";
  }
}

export function verdictLabel(v: Verdict): string {
  switch (v) {
    case "malicious":  return "MALICIOUS";
    case "suspicious": return "SUSPICIOUS";
    case "clean":      return "NO DETECTIONS";
    default:           return "UNKNOWN";
  }
}
