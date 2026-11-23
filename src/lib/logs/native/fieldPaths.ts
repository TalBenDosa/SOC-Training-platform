/**
 * Field rows of a log document, the way a real SIEM document view shows them (Tal, 2026-11-23).
 *
 * The rows follow Kibana / OpenSearch Discover (the Wazuh dashboard is OpenSearch Dashboards):
 *   - a field path is the JSON path with dots and NO array positions: Elasticsearch indexes an
 *     array of objects as one multi-valued field, so `request.ipChain[0].ip` is `request.ipChain.ip`;
 *   - a path that holds several values (an array, or the same leaf in several array items) is ONE
 *     row whose value is the JSON list, in document order: `["Password", "Mobile app notification"]`;
 *   - a name/value parameter list (M365 Parameters / ExtendedProperties / ModifiedProperties,
 *     Google Workspace events.parameters, Entra authenticationProcessingDetails, HTTP header lists)
 *     becomes one field per name, the way the Elastic o365 and google_workspace integrations index
 *     them: `Parameters.ForwardingSmtpAddress`, `events.parameters.message_info.subject`.
 * The record itself never changes: the "Raw log" view still shows the product's exact JSON.
 */

type Json = unknown;
type Obj = Record<string, Json>;

const isObj = (v: Json): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

/** Keys that hold the entry's name in a name/value list. */
const NAME_KEYS = ["name", "Name", "key", "Key"];
/** Keys that hold the entry's value (Google Workspace typed values, M365 Value / NewValue / OldValue). */
const VALUE_KEYS = new Set(["value", "Value", "intValue", "boolValue", "multiValue", "messageValue", "multiMessageValue", "multiIntValue", "multiBoolValue", "NewValue", "OldValue", "newValue", "oldValue"]);
/** Entra modifiedProperties: { displayName, oldValue, newValue }. */
const DISPLAY_NAME_VALUES = new Set(["oldValue", "newValue"]);

function entryName(el: Obj): { name: string; key: string } | null {
  for (const k of NAME_KEYS) if (typeof el[k] === "string" && (el[k] as string) !== "") {
    const rest = Object.keys(el).filter(x => x !== k);
    return rest.length > 0 && rest.every(x => VALUE_KEYS.has(x)) ? { name: el[k] as string, key: k } : null;
  }
  if (typeof el.displayName === "string" && el.displayName !== "") {
    const rest = Object.keys(el).filter(x => x !== "displayName");
    if (rest.length > 0 && rest.every(x => DISPLAY_NAME_VALUES.has(x))) return { name: el.displayName as string, key: "displayName" };
  }
  return null;
}

/** The array is a name/value list: every item names itself once and carries only value keys. */
function asParamList(arr: Json[]): { name: string; key: string; el: Obj }[] | null {
  if (arr.length === 0 || !arr.every(isObj)) return null;
  const out: { name: string; key: string; el: Obj }[] = [];
  const seen = new Set<string>();
  for (const el of arr as Obj[]) {
    const n = entryName(el);
    if (n === null || seen.has(n.name)) return null;
    seen.add(n.name);
    out.push({ ...n, el });
  }
  return out;
}

/** A Google Workspace message value is { parameter: [...] }: its fields are the inner list. */
const unwrapMessage = (m: Json): Json => (isObj(m) && Array.isArray(m.parameter) && Object.keys(m).length === 1 ? m.parameter : m);

function entryValue(el: Obj, nameKey: string): Json | undefined {
  const keys = Object.keys(el).filter(k => k !== nameKey);
  if (keys.length === 0) return undefined;
  if (keys.length === 1) {
    const k = keys[0];
    if (k === "messageValue") return unwrapMessage(el[k]);
    if (k === "multiMessageValue" && Array.isArray(el[k])) return (el[k] as Json[]).map(unwrapMessage);
    // A lone old/new value keeps its own name (ModifiedProperties.<Name>.NewValue), like the Elastic o365 pipeline.
    if (k === "NewValue" || k === "OldValue" || k === "newValue" || k === "oldValue") return { [k]: el[k] };
    return el[k];
  }
  const o: Obj = {};
  for (const k of keys) o[k] = el[k];
  return o;
}

/** Discover-style field rows of a JSON document. */
export function documentRows(record: Obj): [string, string][] {
  // One ordered map: a path keeps the position where the document first reaches it.
  const fields = new Map<string, { values: Json[]; empty?: string }>();
  const slot = (p: string) => { let f = fields.get(p); if (!f) { f = { values: [] }; fields.set(p, f); } return f; };
  const join = (p: string, k: string) => (p ? `${p}.${k}` : k);

  const walk = (v: Json, p: string) => {
    if (v === undefined) return;
    if (Array.isArray(v)) {
      if (v.length === 0) { slot(p).empty ??= "[]"; return; }
      const params = asParamList(v);
      if (params) {
        for (const { name, key, el } of params) { const x = entryValue(el, key); if (x !== undefined) walk(x, join(p, name)); }
        return;
      }
      for (const x of v) walk(x, p);
      return;
    }
    if (isObj(v)) {
      const e = Object.entries(v);
      if (e.length === 0) { slot(p).empty ??= "{}"; return; }
      for (const [k, x] of e) walk(x, join(p, k));
      return;
    }
    slot(p).values.push(v);
  };
  walk(record, "");

  const paths = [...fields.keys()];
  const out: [string, string][] = [];
  for (const [p, f] of fields) {
    if (f.values.length > 0) {
      // Discover leaves nulls out of a multi-valued field; a field that is only null shows null once.
      const vs = f.values.some(x => x !== null) ? f.values.filter(x => x !== null) : [null];
      out.push([p, vs.length === 1 ? scalar(vs[0]) : listText(vs)]);
    } else if (f.empty && !paths.some(q => q.startsWith(`${p}.`) && (fields.get(q)!.values.length > 0))) {
      // An empty array / object row only when no other item of the same field has values.
      out.push([p, f.empty]);
    }
  }
  return out;
}

const scalar = (v: Json) => (v === null ? "null" : String(v));
/** A multi-valued field as Discover prints it: a JSON list, one space after each comma. */
const listText = (vs: Json[]) => `[${vs.map(v => JSON.stringify(v)).join(", ")}]`;

/** The values of a row (several when the row shows a JSON list). */
export function rowValues(value: string): string[] {
  if (value.startsWith("[") && value.endsWith("]") && value.length > 2) {
    try { const a = JSON.parse(value); if (Array.isArray(a)) return a.map(x => (x !== null && typeof x === "object" ? JSON.stringify(x) : scalar(x))); } catch { /* a plain value */ }
  }
  return [value];
}

const INDEXED = /\[\d+\]/;

/**
 * Authored raw blocks sometimes spell a nested field as one flat key ("targetResources[0].id").
 * Rebuild those keys as the nested document they stand for, so the rows read the same as a native log.
 * Keys without an array position stay as they are.
 */
export function unflattenIndexed(raw: Obj): Obj {
  if (!Object.keys(raw).some(k => INDEXED.test(k))) return raw;
  const out: Obj = {};
  for (const [k, v] of Object.entries(raw)) {
    if (!INDEXED.test(k)) { out[k] = v; continue; }
    const toks: (string | number)[] = [];
    for (const m of k.matchAll(/\[(\d+)\]|([^.[\]]+)/g)) {
      if (m[1] !== undefined) toks.push(Number(m[1]));
      else { const s = m[2].trim(); if (s) toks.push(s); }
    }
    if (toks.length === 0 || typeof toks[0] === "number") { out[k] = v; continue; }
    let cur: Json = out;
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i];
      const last = i === toks.length - 1;
      const nextIsIndex = !last && typeof toks[i + 1] === "number";
      const c = cur as Record<string | number, Json>;
      if (last) { c[t] = v; break; }
      const existing = c[t];
      if (existing === undefined || existing === null || typeof existing !== "object") c[t] = nextIsIndex ? [] : {};
      cur = c[t];
    }
  }
  // Sparse arrays (an authored [1] with no [0]) keep only the items that exist.
  const compact = (v: Json): Json => {
    if (Array.isArray(v)) return v.filter(x => x !== undefined).map(compact);
    if (isObj(v)) { for (const k of Object.keys(v)) v[k] = compact(v[k]); return v; }
    return v;
  };
  return compact(out) as Obj;
}

/** Field rows of an authored raw block: flat keys normalized, nested values expanded. */
export function rawBlockRows(raw: Obj): [string, string][] {
  return documentRows(unflattenIndexed(raw));
}
