/**
 * Analytics rules of the workspace.
 *
 *  - One scheduled rule per detection use case that could fire, its KQL compiled from the use case's
 *    condition onto the mapped columns (mapRow.ts holds the field mapping).
 *  - Noisy rules, the kind real SOCs run (noise.ts).
 *
 * A threshold rule is written the way a real scheduled rule is: a plain summarize. The window is the
 * rule's lookback, which the scheduler applies as the query's time range.
 */
import { NATIVE_SOURCES, stackFor, useCasesFor as casesForSource, type Stack } from "@/lib/logs/native";
import type { Condition, SourceId, UseCase } from "@/lib/logs/native/types";
import { tacticById, techniqueById } from "@/lib/mitre/attack";
import { fieldOn, specFor, type FieldRef, type Spec } from "./mapRow";
import type { AnalyticsRule, SentinelSeverity } from "./types";

export const kstr = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r")}"`;
const verbatim = (s: string) => `@"${s.replace(/"/g, '""')}"`;

const NUMERIC = new Set(["int", "long", "real"]);

/** The text of a field, for string operators on a non-string column. */
const asText = (ref: FieldRef) => (ref.type === "string" ? ref.expr : `tostring(${ref.expr})`);

/** JS \uXXXX escapes as RE2 writes them. */
const re2 = (pattern: string) => pattern.replace(/\\u([0-9a-fA-F]{4})/g, "\\x{$1}");

/**
 * A regex on a field that sits inside JSON text: anchors bind to the JSON value, not to the column.
 * Keeps the pattern's meaning for one element without expanding the array in every rule.
 */
function textRegex(ref: FieldRef, path: string, pattern: string): string {
  const start = pattern.startsWith("^"), end = pattern.endsWith("$") && !pattern.endsWith("\\$");
  const core = pattern.slice(start ? 1 : 0, end ? -1 : undefined);
  const open = path.endsWith("[]") ? '"' : `"${ref.key}":"`;
  return `${open}${start ? "" : String.raw`(?:[^"\\]|\\.)*`}(?:${core})${end ? '"' : ""}`;
}

function isNum(v: unknown): boolean { return typeof v === "number" || (typeof v === "string" && v.trim() !== "" && !Number.isNaN(Number(v))); }

/** A field compared with one value, honouring the column's real type. */
function eqExpr(ref: FieldRef, value0: unknown, path: string): string {
  const value = ref.values?.[String(value0)] ?? value0;
  if (value === "") return `isempty(${asText(ref)})`;
  if (ref.inText) {
    const primitive = path.endsWith("[]");
    if (primitive) return `${ref.expr} contains_cs ${kstr(JSON.stringify(String(value)))}`;
    const quoted = typeof value === "string" ? JSON.stringify(value) : String(value);
    return `${ref.expr} contains_cs ${kstr(`"${ref.key}":${quoted}`)}`;
  }
  if (ref.type === "bool") return `${ref.expr} == ${String(value).toLowerCase() === "true"}`;
  if (NUMERIC.has(ref.type)) return isNum(value) ? `${ref.expr} == ${Number(value)}` : `tostring(${ref.expr}) == ${kstr(String(value))}`;
  return `${ref.expr} == ${kstr(String(value))}`;
}

function cidrExpr(expr: string, value: unknown): string {
  const list = (Array.isArray(value) ? value : [value]).map(String);
  return list.length === 1 ? `ipv4_is_in_range(${expr}, ${kstr(list[0])})` : `(${list.map(c => `ipv4_is_in_range(${expr}, ${kstr(c)})`).join(" or ")})`;
}

function leaf(spec: Spec, c: { field: string; op: string; value?: unknown }): string | null {
  const ref = fieldOn(spec, c.field);
  if (!ref) return null;
  const text = asText(ref);
  const v = c.value;
  switch (c.op) {
    case "eq": return eqExpr(ref, v, c.field);
    case "neq": return `(isnotempty(${text}) and not(${eqExpr(ref, v, c.field)}))`;
    case "in": return `(${(v as unknown[]).map(x => eqExpr(ref, x, c.field)).join(" or ")})`;
    case "nin": return `(isnotempty(${text}) and not(${(v as unknown[]).map(x => eqExpr(ref, x, c.field)).join(" or ")}))`;
    case "contains": return `${text} contains_cs ${kstr(String(v))}`;
    case "icontains": return `${text} contains ${kstr(String(v))}`;
    case "startsWith": return `${text} startswith_cs ${kstr(String(v))}`;
    case "endsWith": return `${text} endswith_cs ${kstr(String(v))}`;
    case "regex": { const p = re2(String(v)); return `${text} matches regex ${verbatim(`(?i)${ref.inText ? textRegex(ref, c.field, p) : p}`)}`; }
    case "exists": return `isnotempty(${text})`;
    case "missing": return `isempty(${text})`;
    case "gt": return `toreal(${ref.expr}) > ${Number(v)}`;
    case "gte": return `toreal(${ref.expr}) >= ${Number(v)}`;
    case "lt": return `toreal(${ref.expr}) < ${Number(v)}`;
    case "lte": return `toreal(${ref.expr}) <= ${Number(v)}`;
    case "cidr": return cidrExpr(text, v);
    // A value that is no address (an AWS service name) is outside every range.
    case "notCidr": return `(isnotempty(${text}) and (isnull(parse_ipv4(${text})) or not(${cidrExpr(text, v)})))`;
    default: return null;
  }
}

function cond(spec: Spec, c: Condition): string | null {
  if ("all" in c) {
    const parts = c.all.map(x => cond(spec, x));
    return parts.some(p => p === null) ? null : parts.length === 1 ? parts[0] : `(${parts.join(" and ")})`;
  }
  if ("any" in c) {
    const parts = c.any.map(x => cond(spec, x));
    return parts.some(p => p === null) ? null : parts.length === 1 ? parts[0] : `(${parts.join(" or ")})`;
  }
  if ("not" in c) {
    const p = cond(spec, c.not);
    return p === null ? null : `not(${p})`;
  }
  return leaf(spec, c);
}

/** Native kinds a use case runs on, grouped by the spec (table) they land in. */
function specsOf(uc: UseCase, cloud?: SourceId): { spec: Spec; kinds: string[] }[] {
  const all = uc.kinds ?? Object.keys(NATIVE_SOURCES[uc.sourceId]?.schema.kinds ?? {});
  const out = new Map<Spec, string[]>();
  for (const k of all) {
    const spec = specFor(uc.sourceId, k, cloud);
    if (!spec) continue;
    out.set(spec, [...(out.get(spec) ?? []), k]);
  }
  return [...out].map(([spec, kinds]) => ({ spec, kinds }));
}

function kindClause(spec: Spec, kinds: string[], restricted: boolean): string | null {
  if (!restricted || !spec.kindFilter) return null;
  const parts = kinds.map(k => spec.kindFilter!(k)).filter((p): p is string => !!p);
  if (!parts.length) return null;
  return parts.length === 1 ? parts[0] : `(${parts.join(" or ")})`;
}

/** Table + where lines of one use case on one spec. */
function baseQuery(uc: UseCase, spec: Spec, kinds: string[]): string | null {
  const body = cond(spec, uc.match);
  if (body === null) return null;
  const lines = [spec.table];
  if (spec.base) lines.push(`| where ${spec.base}`);
  const k = kindClause(spec, kinds, !!uc.kinds);
  if (k) lines.push(`| where ${k}`);
  lines.push(`| where ${body}`);
  return lines.join("\n");
}

/** The grouping expression of one threshold key ("a||b" coalesces). */
function groupExpr(spec: Spec, group: string): string | null {
  const refs = group.split("||").map(p => fieldOn(spec, p.trim()));
  if (refs.some(r => !r)) return null;
  const exprs = refs.map(r => (r!.type === "string" ? r!.expr : `tostring(${r!.expr})`));
  return exprs.length === 1 ? exprs[0] : `coalesce(${exprs.join(", ")})`;
}

const alias = (expr: string, i: number) => (/^[A-Za-z_][A-Za-z0-9_]*$/.test(expr) ? expr : `Key${i + 1}`);

function thresholdTail(uc: UseCase, spec: Spec): string | null {
  const t = uc.threshold!;
  const keys = t.groupBy.map(g => groupExpr(spec, g));
  if (keys.some(k => k === null)) return null;
  const by = keys.map((k, i) => (alias(k!, i) === k ? k! : `${alias(k!, i)} = ${k}`)).join(", ");
  const distinct = t.distinct ? fieldOn(spec, t.distinct) : null;
  if (t.distinct && !distinct) return null;
  const measure = distinct ? `dcount(${distinct.expr})` : "count()";
  return `| summarize Count = ${measure}, StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by ${by}\n| where Count >= ${t.count}`;
}

/** A threshold across tables: each table projects the same keys, the union is summarized. */
function unionThreshold(uc: UseCase, bases: { spec: Spec; query: string }[]): string | null {
  const t = uc.threshold!;
  const parts: string[] = [];
  for (const b of bases) {
    const keys = t.groupBy.map(g => groupExpr(b.spec, g));
    const distinct = t.distinct ? fieldOn(b.spec, t.distinct) : null;
    if (keys.some(k => k === null) || (t.distinct && !distinct)) return null;
    const cols = keys.map((k, i) => `Key${i + 1} = ${k}`);
    if (distinct) cols.push(`Measure = ${distinct.expr}`);
    parts.push(`(${b.query.replace(/\n/g, "\n  ")}\n  | project TimeGenerated, ${cols.join(", ")})`);
  }
  const by = t.groupBy.map((_, i) => `Key${i + 1}`).join(", ");
  const measure = t.distinct ? "dcount(Measure)" : "count()";
  return `union\n${parts.join(",\n")}\n| summarize Count = ${measure}, StartTime = min(TimeGenerated), EndTime = max(TimeGenerated) by ${by}\n| where Count >= ${t.count}`;
}

/** KQL lines that keep one threshold group, from the key the use-case engine reports. */
export function groupFilter(uc: UseCase, spec: Spec, groupKey: string | undefined): string[] {
  if (!uc.threshold || groupKey === undefined) return [];
  const values = groupKey.split("|");
  if (values.length !== uc.threshold.groupBy.length) return [];
  return uc.threshold.groupBy.flatMap((g, i) => {
    const expr = groupExpr(spec, g);
    return expr && values[i] ? [`| where ${expr} == ${kstr(values[i])}`] : [];
  });
}

export interface CompiledRule {
  /** Per table: the row-level query (no aggregation). */
  bases: { spec: Spec; query: string }[];
  /** The rule's full KQL. */
  query: string;
  tables: string[];
}

const compiled = new Map<string, CompiledRule | null>();

/** The use case as KQL over the mapped tables, or null when no table holds what it reads. */
export function compileUseCase(uc: UseCase, cloud?: SourceId): CompiledRule | null {
  const key = `${cloud ?? ""}|${uc.id}`;
  const hit = compiled.get(key);
  if (hit !== undefined) return hit;
  const bases: CompiledRule["bases"] = [];
  const tails: string[] = [];
  for (const { spec, kinds } of specsOf(uc, cloud)) {
    const q = baseQuery(uc, spec, kinds);
    if (q === null) continue;
    bases.push({ spec, query: q });
    if (uc.threshold) {
      const tail = thresholdTail(uc, spec);
      if (tail) tails.push(`${q}\n${tail}`);
    }
  }
  let out: CompiledRule | null = null;
  if (bases.length) {
    let query: string | null = null;
    if (uc.threshold && bases.length > 1) query = unionThreshold(uc, bases);
    else {
      const parts = uc.threshold ? tails : bases.map(b => b.query);
      if (parts.length) query = parts.length === 1 ? parts[0] : `union\n${parts.map(p => `(${p.replace(/\n/g, "\n  ")})`).join(",\n")}`;
    }
    if (query) out = { bases, query, tables: [...new Set(bases.map(b => b.spec.table))] };
  }
  compiled.set(key, out);
  return out;
}

/** Console text uses no em dashes. */
export const plain = (s: string) => s.replace(/\s*\u2014\s*/g, ": ");

/** Triage guidance in a rule's description ("Benign under a ticket") stays on the rule page, off the alert. */
const GUIDANCE = /\b(benign|not malicious|false positive|true positive)\b/i;
export const alertDescription = (ruleDescription: string) =>
  plain(ruleDescription).split(/(?<=[.!?])\s+/).filter(sentence => !GUIDANCE.test(sentence)).join(" ");

const SEVERITY: Record<UseCase["severity"], SentinelSeverity> = { critical: "High", high: "High", medium: "Medium", low: "Low" };
export const ruleSeverity = (s: UseCase["severity"]) => SEVERITY[s];

/** Tactic name as Sentinel writes it: no spaces. */
export const tacticName = (name: string) => name.split(/[\s-]+/).map(w => w[0].toUpperCase() + w.slice(1)).join("");

export function tacticsOf(techniques: string[]): string[] {
  const out = new Set<string>();
  for (const id of techniques) {
    const t = techniqueById(id) ?? techniqueById(id.split(".")[0]);
    if (!t) continue;
    const name = tacticById(t.tactic)?.name;
    if (name) out.add(tacticName(name));
  }
  return [...out];
}

const human = (sec: number) => (sec % 3600 === 0 ? `${sec / 3600} hour${sec === 3600 ? "" : "s"}` : `${Math.round(sec / 60)} minutes`);

function fromUseCase(uc: UseCase, c: CompiledRule): AnalyticsRule {
  const window = uc.threshold?.windowSec;
  return {
    id: uc.id, name: plain(uc.title), severity: SEVERITY[uc.severity], tactics: tacticsOf(uc.mitre), techniques: uc.mitre, description: plain(uc.description), query: c.query,
    frequency: window ? human(Math.max(300, Math.min(window, 3600))) : "5 minutes", lookback: window ? human(Math.max(window, 300)) : "1 hour",
    dataSources: c.tables, falsePositives: (uc.falsePositives ?? []).map(plain),
  };
}

/** Sources whose records a shop can hold whatever its stack says. */
const ALWAYS: SourceId[] = ["windows_security", "sysmon", "linux_auditd", "aws_cloudtrail", "aws_guardduty", "aws_vpcflow", "azure_activity", "gcp_audit", "m365"];

/** The use cases that could fire under a stack: their source is in the stack and a real table holds them. */
export function stackUseCases(companyId: string, stack?: Stack): { uc: UseCase; compiled: CompiledRule }[] {
  const eff = stackFor(companyId, stack);
  const sources = new Set<SourceId>([...ALWAYS, ...(Object.values(eff) as SourceId[])]);
  const out: { uc: UseCase; compiled: CompiledRule }[] = [];
  for (const uc of casesForSource()) {
    if (!sources.has(uc.sourceId)) continue;
    const c = compileUseCase(uc, eff.cloud);
    if (c) out.push({ uc, compiled: c });
  }
  return out;
}

export function buildRules(companyId: string, stack?: Stack): AnalyticsRule[] {
  return stackUseCases(companyId, stack).map(x => fromUseCase(x.uc, x.compiled));
}
