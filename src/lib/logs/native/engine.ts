/**
 * Use-case (detection rule) engine. Evaluates {@link UseCase}s over native logs so
 * every use case shipped with a source is tested: the attack logs must trigger it,
 * and it must stay quiet on ordinary noise. The same rules are shown to students
 * (title / description / logic) as the detections a SOC would write on these logs.
 */
import type { Condition, NativeLog, UseCase, UseCaseHit } from "./types";
import { getAll } from "./paths";

function ipToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  return ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + +m[4];
}
function inCidr(ip: string, cidr: string): boolean {
  const [net, bitsS] = cidr.split("/");
  const a = ipToInt(ip), b = ipToInt(net);
  if (a === null || b === null) return false;
  const bits = Number(bitsS ?? 32);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}
const num = (v: unknown) => (typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" && !isNaN(Number(v)) ? Number(v) : NaN);

function test(v: unknown, op: string, value: unknown): boolean {
  const s = v === null || v === undefined ? "" : String(v);
  switch (op) {
    case "eq": return typeof value === "number" ? num(v) === value : typeof value === "boolean" ? v === value || s === String(value) : s === String(value);
    case "neq": return !test(v, "eq", value);
    case "in": return Array.isArray(value) && value.some(x => test(v, "eq", x));
    case "nin": return !test(v, "in", value);
    case "contains": return s.includes(String(value));
    case "icontains": return s.toLowerCase().includes(String(value).toLowerCase());
    case "startsWith": return s.startsWith(String(value));
    case "endsWith": return s.endsWith(String(value));
    case "regex": return new RegExp(String(value), "i").test(s);
    case "gt": return num(v) > Number(value);
    case "gte": return num(v) >= Number(value);
    case "lt": return num(v) < Number(value);
    case "lte": return num(v) <= Number(value);
    case "cidr": return (Array.isArray(value) ? value : [value]).some(c => inCidr(s, String(c)));
    case "notCidr": return s !== "" && !(Array.isArray(value) ? value : [value]).some(c => inCidr(s, String(c)));
    default: return false;
  }
}

export function matches(record: Record<string, unknown>, c: Condition): boolean {
  if ("all" in c) return c.all.every(x => matches(record, x));
  if ("any" in c) return c.any.some(x => matches(record, x));
  if ("not" in c) return !matches(record, c.not);
  const vals = getAll(record, c.field);
  if (c.op === "exists") return vals.some(v => v !== undefined && v !== null && v !== "");
  if (c.op === "missing") return !vals.some(v => v !== undefined && v !== null && v !== "");
  // Negative ops hold only if NO value matches the positive form.
  if (c.op === "neq" || c.op === "nin" || c.op === "notCidr") return vals.length > 0 && vals.every(v => test(v, c.op, c.value));
  return vals.some(v => test(v, c.op, c.value));
}

/** Run one use case over a set of logs (any sources — non-matching sources are skipped). */
export function runUseCase(uc: UseCase, logs: NativeLog[]): UseCaseHit[] {
  const idx: number[] = [];
  logs.forEach((l, i) => {
    if (l.sourceId !== uc.sourceId) return;
    if (uc.kinds && !uc.kinds.includes(l.kind)) return;
    if (matches(l.record, uc.match)) idx.push(i);
  });
  if (!uc.threshold) return idx.length ? idx.map(i => ({ useCaseId: uc.id, records: [i] })) : [];
  const { groupBy, count, windowSec, distinct } = uc.threshold;
  const groups = new Map<string, number[]>();
  // A groupBy entry may list alternatives "a||b": the first non-empty wins (the same
  // value printed under different keys by different message kinds, e.g. ASA 113005 vs 113039).
  const pick = (rec: Record<string, unknown>, g: string) => {
    for (const alt of g.split("||")) { const v = getAll(rec, alt.trim())[0]; if (v !== undefined && v !== null && v !== "") return String(v); }
    return "";
  };
  for (const i of idx) {
    const key = groupBy.map(g => pick(logs[i].record, g)).join("|");
    groups.set(key, [...(groups.get(key) ?? []), i]);
  }
  const hits: UseCaseHit[] = [];
  for (const [key, members] of groups) {
    const sorted = [...members].sort((a, b) => logs[a].timeMs - logs[b].timeMs);
    let lo = 0;
    for (let hi = 0; hi < sorted.length; hi++) {
      while (logs[sorted[hi]].timeMs - logs[sorted[lo]].timeMs > windowSec * 1000) lo++;
      const win = sorted.slice(lo, hi + 1);
      const size = distinct ? new Set(win.map(i => String(getAll(logs[i].record, distinct)[0] ?? ""))).size : win.length;
      if (size >= count) { hits.push({ useCaseId: uc.id, records: win, groupKey: key }); break; }
    }
  }
  return hits;
}
