/**
 * The practice room for a missed attack log, by its MITRE technique (2026-10-18 review: the
 * after-action report listed what the team walked past, DNS tunnelling, cloud exfiltration,
 * deepfake payment fraud, MCP tool abuse, but never where to learn it). Client-safe: built on
 * ROOMS_META, whose task techniques are taught content, not answers.
 */
import { ROOMS_META } from "@/data/roomsMeta";

const base = (t: string) => t.trim().toUpperCase().split(".")[0];

/** technique (exact or parent) → rooms that practise it, exact matches first. */
let index: Map<string, { id: string; title: string; exact: boolean }[]> | null = null;
function build() {
  const m = new Map<string, { id: string; title: string; exact: boolean }[]>();
  for (const r of ROOMS_META) {
    const techs = new Set(r.tasks.map(t => (t.mitreTechnique ?? "").trim().toUpperCase()).filter(Boolean));
    for (const t of techs) {
      for (const [key, exact] of [[t, true], [base(t), false]] as const) {
        const list = m.get(key) ?? [];
        if (!list.some(x => x.id === r.id)) list.push({ id: r.id, title: r.title, exact });
        m.set(key, list);
      }
    }
  }
  return m;
}

export function practiceFor(technique: string | undefined | null): { id: string; title: string } | null {
  if (!technique) return null;
  index ??= build();
  const t = technique.trim().toUpperCase();
  const hit = index.get(t)?.[0] ?? index.get(base(t))?.find(x => x.exact) ?? index.get(base(t))?.[0];
  return hit ? { id: hit.id, title: hit.title } : null;
}
