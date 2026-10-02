import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { REPORT_VERSION } from "./report/computeReport";

// The report build itself is covered elsewhere — here it is a slow stub we can count.
const build = vi.fn();
vi.mock("./report/serverReport", () => ({ buildServerReport: (...a: unknown[]) => build(...a) }));

import { loadOrBuildReport, awardTeamXpOnce, sessionsMissingXp, ReportBuildingError, xpFromReport } from "./awardTeamXp";

/** A tiny in-memory stand-in for the service-role client (only what awardTeamXp touches). */
function fakeAdmin(opts: { leaseFn?: boolean; xpColumn?: boolean; sessions?: { id: string; status: string; ended_at: string; xp_awarded_at: string | null }[]; xpRows?: { session_id: string }[] } = {}) {
  const leases = new Set<string>();
  const db = { reports: new Map<string, unknown>(), rpcs: [] as string[] };
  const sessions = opts.sessions ?? [];
  const admin = {
    rpc: async (name: string, args: Record<string, unknown>) => {
      db.rpcs.push(name);
      if (name === "team_try_lease") {
        if (opts.leaseFn === false) return { data: null, error: { message: "Could not find the function public.team_try_lease" } };
        const k = `${args.p_session}:${args.p_kind}`;
        if (leases.has(k)) return { data: false, error: null };
        leases.add(k); return { data: true, error: null };
      }
      if (name === "team_release_lease") { leases.delete(`${args.p_session}:${args.p_kind}`); return { data: null, error: null }; }
      if (name === "award_team_session_xp") return { data: 1, error: null };
      return { data: null, error: { message: `unknown rpc ${name}` } };
    },
    from: (table: string) => {
      const q: Record<string, unknown> = {};
      const filters: [string, string, unknown][] = [];
      const builder = {
        select: () => builder,
        eq: (c: string, v: unknown) => { filters.push(["eq", c, v]); return builder; },
        in: (c: string, v: unknown) => { filters.push(["in", c, v]); return builder; },
        is: (c: string, v: unknown) => { filters.push(["is", c, v]); return builder; },
        order: (c: string, o: { ascending: boolean }) => { q.order = [c, o.ascending]; return builder; },
        limit: (n: number) => { q.limit = n; return builder; },
        maybeSingle: async () => ({ data: table === "team_session_reports" ? (db.reports.has(String(filters[0][2])) ? { report: db.reports.get(String(filters[0][2])) } : null) : null, error: null }),
        upsert: async (row: { session_id: string; report: unknown }) => { db.reports.set(row.session_id, row.report); return { error: null }; },
        then: (resolve: (v: unknown) => void) => {
          if (table === "team_sessions") {
            if (filters.some(f => f[0] === "is") && opts.xpColumn === false) return resolve({ data: null, error: { message: "column team_sessions.xp_awarded_at does not exist" } });
            let rows = sessions.filter(s => ["ended", "debriefed"].includes(s.status));
            if (filters.some(f => f[0] === "is")) rows = rows.filter(s => s.xp_awarded_at == null);
            rows = rows.sort((a, b) => (q.order as [string, boolean])[1] ? a.ended_at.localeCompare(b.ended_at) : b.ended_at.localeCompare(a.ended_at));
            return resolve({ data: rows.slice(0, (q.limit as number) ?? 1000).map(s => ({ id: s.id })), error: null });
          }
          if (table === "team_session_xp") return resolve({ data: opts.xpRows ?? [], error: null });
          return resolve({ data: [], error: null });
        },
      };
      return builder;
    },
  };
  return { admin: admin as unknown as SupabaseClient, db };
}

const report = (n = 1) => ({ team: { version: REPORT_VERSION, n }, perUser: [], answers: {} });

beforeEach(() => { build.mockReset(); });

describe("loadOrBuildReport — single-flight (QA M5)", () => {
  it("a herd of concurrent viewers triggers ONE build; the rest read the cached row", async () => {
    const { admin } = fakeAdmin();
    build.mockImplementation(async () => { await new Promise(r => setTimeout(r, 30)); return report(); });
    const results = await Promise.all(Array.from({ length: 5 }, () => loadOrBuildReport(admin, "s1", { pollMs: 10, waitMs: 2000 })));
    expect(build).toHaveBeenCalledTimes(1);
    expect(results.filter(r => r.fresh)).toHaveLength(1);
    expect(results.every(r => (r.report.team as { n?: number }).n === 1)).toBe(true);
  });

  it("a waiter gives up with ReportBuildingError when the build doesn't land in time", async () => {
    const { admin } = fakeAdmin();
    let release!: () => void;
    build.mockImplementation(() => new Promise(r => { release = () => r(report()); }));
    const first = loadOrBuildReport(admin, "s1");
    await new Promise(r => setTimeout(r, 0));
    await expect(loadOrBuildReport(admin, "s1", { pollMs: 5, waitMs: 20 })).rejects.toBeInstanceOf(ReportBuildingError);
    release();
    await first;
  });

  it("a current cached report is served without a build or a lease", async () => {
    const { admin, db } = fakeAdmin();
    db.reports.set("s1", report(7));
    const r = await loadOrBuildReport(admin, "s1");
    expect(r.fresh).toBe(false);
    expect(build).not.toHaveBeenCalled();
    expect(db.rpcs).not.toContain("team_try_lease");
  });

  it("before migration 0088 (no lease function) everyone may build, as before", async () => {
    const { admin } = fakeAdmin({ leaseFn: false });
    build.mockResolvedValue(report());
    await loadOrBuildReport(admin, "s1");
    expect(build).toHaveBeenCalledTimes(1);
  });
});

describe("awardTeamXpOnce", () => {
  it("runs the award once while a concurrent caller holds the xp lease", async () => {
    const { admin, db } = fakeAdmin();
    const r = report() as unknown as Parameters<typeof xpFromReport>[0];
    const [a, b] = await Promise.all([awardTeamXpOnce(admin, "s1", r), awardTeamXpOnce(admin, "s1", r)]);
    expect([a, b].filter(x => x === null)).toHaveLength(1);
    expect(db.rpcs.filter(n => n === "award_team_session_xp")).toHaveLength(1);
  });
});

describe("sessionsMissingXp (QA L5)", () => {
  const sessions = [
    { id: "zero-players", status: "ended", ended_at: "2026-09-01", xp_awarded_at: "2026-09-02" },   // stamped even with no rows
    { id: "old", status: "ended", ended_at: "2026-08-01", xp_awarded_at: null },
    { id: "new", status: "ended", ended_at: "2026-10-01", xp_awarded_at: null },
    { id: "live", status: "running", ended_at: "", xp_awarded_at: null },
  ];
  it("selects ended sessions never awarded, newest first — an awarded zero-player session never returns", async () => {
    const { admin } = fakeAdmin({ sessions });
    expect(await sessionsMissingXp(admin, 20)).toEqual(["new", "old"]);
  });
  it("falls back to the old rule while the column doesn't exist yet", async () => {
    const { admin } = fakeAdmin({ sessions, xpColumn: false, xpRows: [{ session_id: "old" }] });
    expect(await sessionsMissingXp(admin, 20)).toEqual(["new", "zero-players"]);
  });
});
