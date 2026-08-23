import "server-only";
import { randomUUID } from "crypto";
import type { TelemetryEvent, LogSource, EventType } from "@/lib/sim/types";
import { LOG_SOURCES, EVENT_TYPES } from "@/lib/scenarios/authoredConstants";

/**
 * Authored live-feed environment (Phase 3b — migration 0044). An org authors a
 * custom "company": profile + benign background noise + one attack story. Stored
 * as a single content_companies.content jsonb (NO answer-key split — the live
 * feed never client-scores detection; see 0044's header).
 *
 * normalizeCompany is the only producer of that content: it allowlist-rebuilds
 * every field and namespaces the id `org-<org8>-…` so it can never collide with
 * a built-in company id. The stored shape is already dashboard-ready:
 *   { kind:"authored", id, profile{…, architecture{…, sources}}, benignEvents[],
 *     story{ id, title, mitre[], events[], complexity } }
 */

export interface AuthoredCompanyInput {
  id?: string;
  name?: unknown;
  industry?: unknown;
  tagline?: unknown;
  description?: unknown;
  size?: unknown;
  hq?: unknown;
  sources?: unknown;
  baseTime?: unknown;
  benignEvents?: unknown;
  story?: unknown;
}

export type CompanyNormalizeResult =
  | { ok: true; id: string; content: Record<string, unknown> }
  | { ok: false; error: string };

const str = (v: unknown, max: number) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const strArr = (v: unknown, max: number, cap = 20) =>
  Array.isArray(v) ? v.map(x => str(x, max)).filter(Boolean).slice(0, cap) : [];
const num = (v: unknown, def: number, min: number, maxV: number) => {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? Math.min(maxV, Math.max(min, Math.round(n))) : def;
};
function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "company";
}
function newId(orgId: string, name: string): string {
  const ns = orgId.replace(/-/g, "").slice(0, 8);
  return `org-${ns}-${slugify(name)}-${randomUUID().slice(0, 4)}`;
}
export function isOrgCompanyIdFor(id: string, orgId: string): boolean {
  const ns = orgId.replace(/-/g, "").slice(0, 8);
  return typeof id === "string" && id.startsWith(`org-${ns}-`);
}

function parseRaw(text: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (typeof text !== "string") return out;
  for (const line of text.split("\n").slice(0, 60)) {
    const i = line.indexOf(":");
    if (i <= 0) continue;
    const k = line.slice(0, i).trim().slice(0, 80);
    const v = line.slice(i + 1).trim().slice(0, 400);
    if (k) out[k] = v;
  }
  return out;
}

function buildEvents(
  raw: unknown, idPrefix: string, base: Date,
  opts: { severity: TelemetryEvent["severity"]; withMitre?: boolean; cap: number },
): TelemetryEvent[] {
  const arr = Array.isArray(raw) ? raw : [];
  return arr
    .map((e, i): TelemetryEvent | null => {
      const o = (e ?? {}) as Record<string, unknown>;
      const description = str(o.description, 1000);
      if (!description) return null;
      const source = (LOG_SOURCES.includes(str(o.source, 40) as LogSource) ? str(o.source, 40) : "siem") as LogSource;
      const event_type = (EVENT_TYPES.includes(str(o.eventType, 40) as EventType) ? str(o.eventType, 40) : "edr_alert") as EventType;
      const ts = new Date(base.getTime() + num(o.offsetMin, i, 0, 100000) * 60000).toISOString();
      const ev: TelemetryEvent = {
        id: `${idPrefix}${i + 1}`, ts, source, event_type, description,
        severity: opts.severity, raw: parseRaw(o.rawText),
      };
      if (opts.withMitre) {
        const mt = str(o.mitreTechnique, 20);
        if (mt) ev.mitre_technique = mt;
      }
      return ev;
    })
    .filter((e): e is TelemetryEvent => e !== null)
    .slice(0, opts.cap);
}

export function normalizeCompany(orgId: string, input: AuthoredCompanyInput): CompanyNormalizeResult {
  const name = str(input.name, 120);
  if (!name) return { ok: false, error: "Give the company a name." };

  const id = input.id && isOrgCompanyIdFor(str(input.id, 120), orgId) ? str(input.id, 120) : newId(orgId, name);
  const base = (() => {
    const t = typeof input.baseTime === "string" ? new Date(input.baseTime) : new Date();
    return Number.isNaN(t.getTime()) ? new Date() : t;
  })();

  const sources = (strArr(input.sources, 40, 16).filter(s => LOG_SOURCES.includes(s as LogSource))) as LogSource[];
  if (sources.length === 0) return { ok: false, error: "Pick at least one active log source for this environment." };

  const benignEvents = buildEvents(input.benignEvents, `${id}-b`, base, { severity: "informational", cap: 40 });
  if (benignEvents.length === 0) return { ok: false, error: "Add at least one benign background event." };

  const storyIn = (input.story ?? {}) as Record<string, unknown>;
  const storyTitle = str(storyIn.title, 200);
  if (!storyTitle) return { ok: false, error: "Give the attack story a title." };
  const storyEvents = buildEvents(storyIn.events, `${id}-a`, base, { severity: "high", withMitre: true, cap: 30 });
  if (storyEvents.length === 0) return { ok: false, error: "Add at least one attack-story event." };
  // Prefer explicit mitre, else derive from the events' techniques.
  const mitre = strArr(storyIn.mitre, 20, 12);
  const derivedMitre = [...new Set(storyEvents.map(e => e.mitre_technique).filter((m): m is string => !!m))];
  const finalMitre = mitre.length ? mitre : derivedMitre;

  const content = {
    kind: "authored",
    id,
    // Top-level name/title so the content_companies.title generated column
    // (content->>'name') and the manage list (content.title) both resolve.
    name,
    title: name,
    profile: {
      id,
      name,
      tagline: str(input.tagline, 160),
      industry: str(input.industry, 80) || "Technology",
      size: num(input.size, 500, 1, 1_000_000),
      hq: str(input.hq, 80),
      description: str(input.description, 800),
      gradient: "from-cyber-500/20 to-neon-purple/20",
      architecture: {
        edr: "—", cloud: "—", idp: "—", email: "—", firewall: "—", vpn: "—",
        sources,
      },
    },
    benignEvents,
    story: {
      id: `${id}-story`,
      title: storyTitle,
      mitre: finalMitre,
      events: storyEvents,
      complexity: "core" as const,
    },
  };
  return { ok: true, id, content };
}
