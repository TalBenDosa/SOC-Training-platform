/**
 * Input sanitising for learning plans — PURE functions (no DB, no corpus), so
 * they are unit-tested directly (sanitize.test.ts) and shared by every org route.
 *
 * The rule throughout is allowlist-rebuild, never spread: a field the client
 * invents cannot ride along into a stored row, and an id only survives if the
 * caller-supplied `isKnown` says it exists in the catalogue (built-in content or
 * the org's own PUBLISHED content).
 */
import {
  DEFAULT_PRIORITY, PLAN_ITEM_KINDS, PLAN_LIMITS, itemKey,
  type Audience, type PlanItem, type PlanItemKind, type Priority,
} from "./types";

/** Strip control characters (keep \n and \t) and trim; cap at `max`. */
export function cleanText(v: unknown, max: number): string {
  if (typeof v !== "string") return "";
  // eslint-disable-next-line no-control-regex
  return v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").trim().slice(0, max);
}

/** Single-line variant for names/titles: newlines collapse to spaces. */
export function cleanLine(v: unknown, max: number): string {
  return cleanText(typeof v === "string" ? v.replace(/[\r\n\t]+/g, " ") : v, max).replace(/\s{2,}/g, " ");
}

/** Coerce to a Priority (1..3); anything else → `fallback`. */
export function parsePriority(v: unknown, fallback: Priority = DEFAULT_PRIORITY): Priority {
  const n = typeof v === "string" ? Number(v) : v;
  return n === 1 || n === 2 || n === 3 ? n : fallback;
}

export function parseAudience(v: unknown): Audience {
  return v === "targeted" ? "targeted" : "org";
}

/**
 * Due date: null/"" clears it, otherwise it must parse to a real date between
 * 2000 and 2100 (guards against typos like year 20266 silently landing).
 *
 * A date-only value ("2026-10-01", what <input type="date"> sends) means "by
 * the end of that day": it is stored as 23:59:59.999 UTC of that calendar date,
 * so the item isn't flagged overdue on its due day, and the UI renders it with
 * formatDueDate() in UTC so the calendar date never shifts by timezone.
 */
export function parseDueDate(v: unknown): { ok: true; value: string | null } | { ok: false } {
  if (v === null || v === undefined || v === "") return { ok: true, value: null };
  if (typeof v !== "string" && typeof v !== "number") return { ok: false };
  if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v)) {
    const d = new Date(`${v}T23:59:59.999Z`);
    // Reject impossible dates ("2026-02-31" would roll over to March).
    if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== v) return { ok: false };
    const y = d.getUTCFullYear();
    return y < 2000 || y > 2100 ? { ok: false } : { ok: true, value: d.toISOString() };
  }
  const d = new Date(v);
  const t = d.getTime();
  if (Number.isNaN(t)) return { ok: false };
  const y = d.getUTCFullYear();
  if (y < 2000 || y > 2100) return { ok: false };
  return { ok: true, value: d.toISOString() };
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (v: unknown): v is string => typeof v === "string" && UUID_RE.test(v);

const isKind = (k: unknown): k is PlanItemKind => typeof k === "string" && (PLAN_ITEM_KINDS as readonly string[]).includes(k);

/**
 * Whitelist + normalise plan items.
 *  - kind must be room | scenario | lesson | quiz, id a short string that
 *    `isKnown(kind, id)` accepts;
 *  - duplicates (same kind:id) keep their FIRST position — order is meaningful;
 *  - priority kept only when it is a valid non-default value, note only when
 *    non-empty (≤ 300 chars) — so a v1 `{kind,id}` row round-trips unchanged;
 *  - capped at `max` items.
 */
/**
 * How many well-formed, distinct items in `raw` did NOT survive sanitising
 * (unknown/unavailable ids). Routes refuse the write when this is > 0 so a plan
 * never silently loses items — e.g. org-authored items dropped because the
 * org-content catalog failed to load.
 */
export function droppedPlanItemCount(raw: unknown, kept: readonly PlanItem[], max: number = PLAN_LIMITS.items): number {
  if (!Array.isArray(raw)) return 0;
  const sent = new Set<string>();
  for (const r of raw) {
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    if (isKind(o.kind) && typeof o.id === "string" && o.id.length > 0 && o.id.length <= 200) sent.add(`${o.kind}${o.id}`);
  }
  return Math.max(0, Math.min(sent.size, max) - kept.length);
}

export function sanitizePlanItems(
  raw: unknown,
  isKnown: (kind: PlanItemKind, id: string) => boolean,
  max: number = PLAN_LIMITS.items,
): PlanItem[] {
  if (!Array.isArray(raw)) return [];
  const out: PlanItem[] = [];
  const seen = new Set<string>();
  for (const r of raw) {
    if (out.length >= max) break;
    if (!r || typeof r !== "object") continue;
    const o = r as Record<string, unknown>;
    const kind = o.kind;
    const id = o.id;
    if (!isKind(kind) || typeof id !== "string" || id.length === 0 || id.length > 200) continue;
    if (!isKnown(kind, id)) continue;
    const key = itemKey({ kind, id });
    if (seen.has(key)) continue;
    seen.add(key);

    const item: PlanItem = { kind, id };
    const priority = parsePriority(o.priority, DEFAULT_PRIORITY);
    if (priority !== DEFAULT_PRIORITY) item.priority = priority;
    const note = cleanText(o.note, PLAN_LIMITS.note);
    if (note) item.note = note;
    out.push(item);
  }
  return out;
}

/**
 * Recipients of a targeted plan: only group ids that belong to the caller's org
 * and user ids that are members of it survive; deduped and capped.
 */
export function sanitizeTargets(
  raw: unknown,
  validGroupIds: ReadonlySet<string>,
  validUserIds: ReadonlySet<string>,
): { group_ids: string[]; user_ids: string[] } {
  const o = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const pick = (v: unknown, valid: ReadonlySet<string>, cap: number) => {
    if (!Array.isArray(v)) return [];
    const out: string[] = [];
    const seen = new Set<string>();
    for (const x of v) {
      if (out.length >= cap) break;
      if (!isUuid(x)) continue;
      const id = x.toLowerCase();
      if (seen.has(id) || !valid.has(id)) continue;
      seen.add(id);
      out.push(id);
    }
    return out;
  };
  return {
    group_ids: pick(o.group_ids, validGroupIds, PLAN_LIMITS.targetGroups),
    user_ids: pick(o.user_ids, validUserIds, PLAN_LIMITS.targetUsers),
  };
}

/** Member ids for a group: uuids that are members of the org, deduped, capped. */
export function sanitizeMemberIds(raw: unknown, validUserIds: ReadonlySet<string>): string[] {
  return sanitizeTargets({ user_ids: raw }, new Set(), validUserIds).user_ids.slice(0, PLAN_LIMITS.groupMembers);
}
