import "server-only";
/**
 * The learning-plan catalogue: every assignable item, as the module TREE the
 * manager ticks from and as a flat INDEX (title + deep link) the routes resolve
 * stored items against. Server-only — it reads the full corpora (quizzes carry
 * their answer keys, scenarios their builders), and the browser only ever gets
 * the plain id/title tree this produces.
 *
 *   Learning Path → path → module → lesson   (LESSON_PATHS, id "{path}--{lesson}")
 *   Rooms         → category → room          (ROOMS_META)
 *   Quizzes       → category → quiz          (ALL_QUIZZES)
 *   Scenarios     → difficulty → scenario    (SCENARIOS)
 *   Custom        → type → item              (this org's PUBLISHED authored content)
 *
 * The static part is built once per server instance; the org part is a few
 * small reads (id + title only, via a jsonb path select — never the content).
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { LESSON_PATHS } from "@/lib/lessons/paths";
import { ROOMS_META } from "@/data/roomsMeta";
import { ALL_QUIZZES } from "@/lib/quizzes/data";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { itemKey, type CatalogNode, type PlanItemKind } from "./types";

export interface CatalogEntry {
  kind: PlanItemKind;
  id: string;
  title: string;
  href: string;
  custom?: boolean;
}

export interface PlanCatalog {
  tree: CatalogNode[];
  index: Map<string, CatalogEntry>;
  isKnown: (kind: PlanItemKind, id: string) => boolean;
}

const cap = (s: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);
const DIFF_ORDER = ["beginner", "intermediate", "advanced", "expert"];

/** Group `list` by `groupOf`, keeping first-seen group order (the corpus order is curricular). */
function groupBy<T>(list: readonly T[], groupOf: (t: T) => string): [string, T[]][] {
  const m = new Map<string, T[]>();
  for (const t of list) {
    const g = groupOf(t) || "Other";
    const arr = m.get(g);
    if (arr) arr.push(t); else m.set(g, [t]);
  }
  return [...m.entries()];
}

function leaf(e: CatalogEntry, hint?: string): CatalogNode {
  return { key: itemKey(e), label: e.title, hint, item: { kind: e.kind, id: e.id } };
}

interface StaticCatalog { tree: CatalogNode[]; index: Map<string, CatalogEntry> }
let staticCache: StaticCatalog | null = null;

function buildStatic(): StaticCatalog {
  const index = new Map<string, CatalogEntry>();
  const add = (e: CatalogEntry) => { index.set(itemKey(e), e); return e; };

  const learningPath: CatalogNode = {
    key: "grp:lp",
    label: "Learning Path",
    children: LESSON_PATHS.map(p => ({
      key: `grp:lp:${p.slug}`,
      label: p.title,
      hint: cap(p.difficulty),
      children: p.modules.map(m => ({
        key: `grp:lp:${p.slug}:${m.slug}`,
        label: m.title,
        children: m.lessons.map(l => leaf(add({
          kind: "lesson",
          id: `${p.slug}--${l.slug}`,
          title: l.title,
          href: `/learn/${p.slug}/${l.slug}`,
        }), `${l.kind} · ${l.min}m`)),
      })),
    })),
  };

  const rooms: CatalogNode = {
    key: "grp:rooms",
    label: "Rooms",
    children: groupBy(ROOMS_META, r => r.category).map(([cat, list]) => ({
      key: `grp:rooms:${cat}`,
      label: cat,
      children: list.map(r => leaf(add({ kind: "room", id: r.id, title: r.title, href: `/rooms/${r.id}` }), cap(r.difficulty))),
    })),
  };

  const quizzes: CatalogNode = {
    key: "grp:quizzes",
    label: "Quizzes",
    children: groupBy(ALL_QUIZZES, q => q.category).map(([cat, list]) => ({
      key: `grp:quizzes:${cat}`,
      label: cat,
      children: list.map(q => leaf(add({ kind: "quiz", id: q.slug, title: q.title, href: `/quizzes/${q.slug}` }), q.difficulty)),
    })),
  };

  const byDiff = groupBy(SCENARIOS, s => String(s.difficulty))
    .sort((a, b) => DIFF_ORDER.indexOf(a[0]) - DIFF_ORDER.indexOf(b[0]));
  const scenarios: CatalogNode = {
    key: "grp:scenarios",
    label: "Scenarios",
    children: byDiff.map(([diff, list]) => ({
      key: `grp:scenarios:${diff}`,
      label: cap(diff),
      children: list.map(s => leaf(add({ kind: "scenario", id: s.slug, title: s.title, href: `/scenarios/${s.slug}` }))),
    })),
  };

  return { tree: [learningPath, rooms, quizzes, scenarios], index };
}

function getStatic(): StaticCatalog {
  if (!staticCache) staticCache = buildStatic();
  return staticCache;
}

// ── Org-authored (published) content ────────────────────────────────────────
const ORG_SOURCES: { table: string; kind: PlanItemKind; label: string; href: (id: string) => string }[] = [
  { table: "content_rooms",     kind: "room",     label: "Rooms",     href: id => `/rooms/${encodeURIComponent(id)}` },
  { table: "content_scenarios", kind: "scenario", label: "Scenarios", href: id => `/scenarios/${encodeURIComponent(id)}` },
  { table: "content_quizzes",   kind: "quiz",     label: "Quizzes",   href: id => `/quizzes/${encodeURIComponent(id)}` },
  // Authored lessons live in the /learn library (opened in place, no per-lesson URL).
  { table: "content_lessons",   kind: "lesson",   label: "Lessons",   href: () => `/learn` },
];

async function loadOrgEntries(admin: SupabaseClient, orgId: string): Promise<CatalogEntry[][]> {
  return Promise.all(ORG_SOURCES.map(async src => {
    const { data, error } = await admin
      .from(src.table)
      .select("id, title:content->>title")
      .eq("org_id", orgId)
      .eq("status", "published")
      .order("created_at", { ascending: false })
      .limit(500);
    if (error || !data) return [];
    return (data as { id: string; title: string | null }[])
      .filter(r => typeof r.id === "string" && r.id)
      .map(r => ({ kind: src.kind, id: r.id, title: (r.title || r.id).slice(0, 200), href: src.href(r.id), custom: true }));
  }));
}

/**
 * The full catalogue for one org. Pass `withOrg: false` when every item to be
 * resolved is built-in (no "org-" id) to skip the org reads entirely.
 */
export async function getPlanCatalog(admin: SupabaseClient | null, orgId: string | null, withOrg = true): Promise<PlanCatalog> {
  const st = getStatic();
  const index = new Map(st.index);
  const tree = [...st.tree];

  if (withOrg && admin && orgId) {
    const perSource = await loadOrgEntries(admin, orgId);
    const children: CatalogNode[] = [];
    perSource.forEach((entries, i) => {
      if (entries.length === 0) return;
      for (const e of entries) index.set(itemKey(e), e);
      children.push({
        key: `grp:custom:${ORG_SOURCES[i].kind}`,
        label: ORG_SOURCES[i].label,
        children: entries.map(e => leaf(e, "custom")),
      });
    });
    if (children.length) tree.push({ key: "grp:custom", label: "Custom (your org)", children });
  }

  return { tree, index, isKnown: (kind, id) => index.has(itemKey({ kind, id })) };
}

/** True if any stored item references org-authored content (so the org reads are needed). */
export function needsOrgCatalog(itemsLists: unknown[]): boolean {
  return itemsLists.some(items =>
    Array.isArray(items) && items.some(i => typeof (i as { id?: unknown })?.id === "string" && String((i as { id: string }).id).startsWith("org-")));
}
