/**
 * Sigma for missions: parse a learner's Sigma rule (safe YAML subset) and match it
 * against synthetic events, identically in the browser and on the server.
 *
 *   const p = parseSigma(source);
 *   if (p.ok) matchSigma(p.rule, { Image: "C:\\Windows\\System32\\bitsadmin.exe", ... });
 */
import { resetBudget } from "@/lib/kql/errors";
import { compileSearch, evalCondition, parseCondition, type CompiledSearch, type SigmaCondition } from "./detection";
import { parseYaml, toPlain, YamlError, type YMap, type YNode } from "./yamlLite";

export { parseYaml, YamlError, MAX_YAML_BYTES, MAX_YAML_DEPTH } from "./yamlLite";
export type { YNode } from "./yamlLite";
export type { SigmaCondition } from "./detection";

export interface SigmaRule {
  title: string;
  id?: string;
  status?: string;
  description?: string;
  author?: string;
  date?: string;
  tags: string[];
  level?: string;
  logsource: Record<string, unknown>;
  falsepositives: string[];
  /** Search identifiers in source order. */
  searches: CompiledSearch[];
  /** One entry per condition; the rule matches when any of them is true. */
  conditions: SigmaCondition[];
}

export type SigmaParseResult = { ok: true; rule: SigmaRule; warnings: string[] } | { ok: false; error: { message: string; line: number } };

const LEVELS = ["informational", "low", "medium", "high", "critical"];
const KNOWN_TOP = new Set([
  "title", "id", "name", "status", "description", "author", "date", "modified", "tags", "level", "logsource",
  "detection", "falsepositives", "references", "related", "fields", "license", "scope", "taxonomy",
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const IPV4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const HASH = /^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/;

/** Budget for one matchSigma call; only `|re` values spend it. */
const MATCH_BUDGET = 20_000_000;

function entry(map: YMap, key: string): { node: YNode; line: number } | undefined {
  const e = map.entries.find((x) => x.key === key);
  return e ? { node: e.value, line: e.keyLine } : undefined;
}

function scalarString(map: YMap, key: string): string | undefined {
  const e = entry(map, key);
  if (!e) return undefined;
  if (e.node.kind !== "scalar") throw new YamlError(`'${key}' must be a single value`, e.line);
  return e.node.value === null ? undefined : String(e.node.value);
}

function stringList(map: YMap, key: string): string[] {
  const e = entry(map, key);
  if (!e) return [];
  if (e.node.kind === "scalar") return e.node.value === null ? [] : [String(e.node.value)];
  if (e.node.kind === "seq") {
    return e.node.items.map((it) => {
      if (it.kind !== "scalar") throw new YamlError(`'${key}' must be a list of values`, it.line);
      return String(it.value);
    });
  }
  throw new YamlError(`'${key}' must be a list`, e.line);
}

function buildRule(root: YNode, warnings: string[]): SigmaRule {
  if (root.kind !== "map") throw new YamlError("a Sigma rule must be a map of fields (title:, logsource:, detection: ...)", root.line);

  const title = scalarString(root, "title");
  if (!title) throw new YamlError("missing required field 'title'", 1);

  for (const e of root.entries) {
    if (!KNOWN_TOP.has(e.key)) warnings.push(`line ${e.keyLine}: unknown top-level field '${e.key}'`);
  }

  const id = scalarString(root, "id");
  if (id !== undefined && !UUID.test(id)) warnings.push("'id' should be a UUID (e.g. 5f8d2b0c-1a2b-4c3d-9e8f-0a1b2c3d4e5f)");

  const level = scalarString(root, "level");
  if (level === undefined) warnings.push("rule has no 'level' (informational, low, medium, high or critical)");
  else if (!LEVELS.includes(level)) warnings.push(`'level: ${level}' is not a Sigma level (informational, low, medium, high, critical)`);

  const logsourceEntry = entry(root, "logsource");
  let logsource: Record<string, unknown> = {};
  if (!logsourceEntry) warnings.push("rule has no 'logsource'; backends cannot tell which logs it applies to");
  else if (logsourceEntry.node.kind !== "map") throw new YamlError("'logsource' must be a map (category:, product:, service:)", logsourceEntry.line);
  else logsource = toPlain(logsourceEntry.node) as Record<string, unknown>;

  const det = entry(root, "detection");
  if (!det) throw new YamlError("missing required field 'detection'", root.line);
  if (det.node.kind !== "map") throw new YamlError("'detection' must be a map of search identifiers plus a condition", det.line);

  const condEntry = entry(det.node, "condition");
  if (!condEntry) throw new YamlError("detection has no 'condition'", det.line);

  const searches: CompiledSearch[] = [];
  for (const e of det.node.entries) {
    if (e.key === "condition") continue;
    if (e.key === "timeframe") {
      warnings.push("'timeframe' is ignored here; it only matters for correlation rules");
      continue;
    }
    if (!/^[A-Za-z0-9_]+$/.test(e.key)) throw new YamlError(`search identifier '${e.key}' may only use letters, digits and _`, e.keyLine);
    if (["and", "or", "not", "of", "them", "all", "any"].includes(e.key.toLowerCase())) {
      throw new YamlError(`'${e.key}' is a condition keyword and cannot name a search identifier`, e.keyLine);
    }
    searches.push(compileSearch(e.key, e.value, e.keyLine));
  }
  if (searches.length === 0) throw new YamlError("detection defines no search identifiers (e.g. selection:)", det.line);

  const condSources: { text: string; line: number }[] = [];
  const cn = condEntry.node;
  if (cn.kind === "scalar" && typeof cn.value === "string") condSources.push({ text: cn.value, line: condEntry.line });
  else if (cn.kind === "seq" && cn.items.every((x) => x.kind === "scalar" && typeof x.value === "string")) {
    for (const x of cn.items) condSources.push({ text: String((x as { value: unknown }).value), line: x.line });
  } else throw new YamlError("'condition' must be an expression like 'selection and not filter'", condEntry.line);
  if (condSources.length === 0) throw new YamlError("'condition' is empty", condEntry.line);

  const ids = searches.map((s) => s.id);
  const used = new Set<string>();
  const conditions = condSources.map((c) => {
    const parsed = parseCondition(c.text, ids, c.line);
    parsed.used.forEach((u) => used.add(u));
    return parsed.cond;
  });
  for (const s of searches) if (!used.has(s.id)) warnings.push(`search identifier '${s.id}' is defined but not used in the condition`);

  for (const s of searches) {
    for (const lit of s.literals) {
      const bare = lit.value.replace(/^\*+|\*+$/g, "");
      if (IPV4.test(bare)) warnings.push(`line ${lit.line}: '${lit.field}' matches the literal IP ${bare}; IPs rotate, so the rule is brittle (an IOC, not a behaviour)`);
      else if (HASH.test(bare)) warnings.push(`line ${lit.line}: '${lit.field}' matches a literal hash; one recompile defeats it (an IOC, not a behaviour)`);
    }
  }

  return {
    title,
    id,
    status: scalarString(root, "status"),
    description: scalarString(root, "description"),
    author: scalarString(root, "author"),
    date: scalarString(root, "date"),
    tags: stringList(root, "tags"),
    level,
    logsource,
    falsepositives: stringList(root, "falsepositives"),
    searches,
    conditions,
  };
}

export function parseSigma(source: string): SigmaParseResult {
  try {
    const warnings: string[] = [];
    const rule = buildRule(parseYaml(source), warnings);
    return { ok: true, rule, warnings };
  } catch (e) {
    if (e instanceof YamlError) return { ok: false, error: { message: e.message, line: e.line } };
    return { ok: false, error: { message: `internal error: ${(e as Error).message}`, line: 1 } };
  }
}

/**
 * Evaluates every search identifier (so the UI can show which selections hit) and
 * then the condition. Never throws.
 */
export function matchSigma(rule: SigmaRule, event: Record<string, unknown>): { matched: boolean; selections: Record<string, boolean> } {
  const selections: Record<string, boolean> = {};
  resetBudget(MATCH_BUDGET);
  for (const s of rule.searches) {
    try {
      selections[s.id] = s.test(event);
    } catch {
      selections[s.id] = false;
    }
  }
  const matched = rule.conditions.some((c) => evalCondition(c, selections));
  return { matched, selections };
}
