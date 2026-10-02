/**
 * Test-only stand-in for the service-role Supabase client used by the team routes:
 * every query is recorded as an Op and answered by the test's handler. Not imported
 * by any route (the `_testing` folder is private to the App Router).
 */
export type Filter = [op: string, column: string, value: unknown];
export interface Op {
  table: string;
  action: "select" | "insert" | "update" | "upsert" | "delete";
  filters: Filter[];
  payload?: unknown;
  single: boolean;
}
export type Result = { data?: unknown; error?: { message: string; code?: string } | null; count?: number | null };

export const eqOf = (op: Op, column: string) => op.filters.find(f => f[0] === "eq" && f[1] === column)?.[2];

export function fakeAdmin(handler: (op: Op) => Result, rpc: (name: string, args: Record<string, unknown>) => Result = () => ({ data: null, error: null })) {
  const ops: Op[] = [];
  const rpcs: { name: string; args: Record<string, unknown> }[] = [];
  const from = (table: string) => {
    const op: Op = { table, action: "select", filters: [], single: false };
    const run = (): Result => { ops.push(op); const r = handler(op); return { data: r.data ?? null, error: r.error ?? null, count: r.count ?? null }; };
    const b: Record<string, unknown> = {};
    const chain = (name: string) => (...a: unknown[]) => { op.filters.push([name, String(a[0] ?? ""), a[1]]); return b; };
    for (const f of ["eq", "in", "is", "or", "not", "gt", "lt", "order", "range", "limit"]) b[f] = chain(f);
    b.select = () => b;
    b.insert = (p: unknown) => { op.action = "insert"; op.payload = p; return b; };
    b.update = (p: unknown) => { op.action = "update"; op.payload = p; return b; };
    b.upsert = (p: unknown) => { op.action = "upsert"; op.payload = p; return b; };
    b.delete = () => { op.action = "delete"; return b; };
    b.maybeSingle = async () => { op.single = true; return run(); };
    b.single = async () => { op.single = true; return run(); };
    b.then = (resolve: (v: Result) => unknown, reject?: (e: unknown) => unknown) => { try { return Promise.resolve(run()).then(resolve, reject); } catch (e) { return reject ? reject(e) : Promise.reject(e); } };
    return b;
  };
  const client = {
    from,
    rpc: (name: string, args: Record<string, unknown>) => {
      rpcs.push({ name, args });
      const r = rpc(name, args);
      const res = { data: r.data ?? null, error: r.error ?? null };
      const p = Promise.resolve(res) as Promise<typeof res> & { range: () => Promise<typeof res> };
      p.range = () => Promise.resolve(res);
      return p;
    },
  };
  return { client, ops, rpcs };
}

/** A staff / player user as getAuthedUser returns it. */
export const user = (over: Partial<{ id: string; orgId: string | null; orgRole: string | null; isPlatformAdmin: boolean; orgActive: boolean }> = {}) =>
  ({ id: "u-staff", orgId: "org1", orgRole: "instructor", isPlatformAdmin: false, orgActive: true, ...over });
