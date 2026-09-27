import { describe, it, expect, vi } from "vitest";

// The real catalogue imports the whole content corpus; these tests only need a
// few known items.
vi.mock("./catalog", () => {
  const entries = [
    { kind: "room", id: "intro", title: "Intro", href: "/rooms/intro" },
    { kind: "quiz", id: "mitre", title: "MITRE", href: "/quizzes/mitre" },
  ];
  const index = new Map(entries.map(e => [`${e.kind}:${e.id}`, e]));
  return {
    getPlanCatalog: async () => ({ tree: [], index, isKnown: (k: string, id: string) => index.has(`${k}:${id}`) }),
    needsOrgCatalog: () => false,
  };
});

import { PlanDataError, fetchAll, loadLearnerPlans, loadProgress, toPlanDataError } from "./server";
import type { SupabaseClient } from "@supabase/supabase-js";

// ── A tiny in-memory PostgREST stand-in that records every call ─────────────
type Row = Record<string, unknown>;
type Op = [string, ...unknown[]];
interface Call { table: string; ops: Op[] }

function splitTop(s: string): string[] {
  const out: string[] = []; let depth = 0; let cur = "";
  for (const ch of s) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "," && depth === 0) { out.push(cur); cur = ""; } else cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}
function matchCond(row: Row, cond: string): boolean {
  const [col, op, ...rest] = cond.split(".");
  const val = rest.join(".");
  if (op === "is" && val === "null") return row[col] === null || row[col] === undefined;
  if (op === "eq") return String(row[col]) === val;
  if (op === "in") return val.replace(/^\(|\)$/g, "").split(",").includes(String(row[col]));
  throw new Error(`unsupported cond ${cond}`);
}
function applyOps(rows: Row[], ops: Op[]): Row[] {
  let out = [...rows];
  const orders: string[] = [];
  for (const [op, a, b] of ops) {
    if (op === "eq") out = out.filter(r => String(r[a as string]) === String(b));
    if (op === "in") out = out.filter(r => (b as unknown[]).map(String).includes(String(r[a as string])));
    if (op === "is") out = out.filter(r => (r[a as string] ?? null) === b);
    if (op === "or") out = out.filter(r => splitTop(a as string).some(c => matchCond(r, c)));
    if (op === "order") orders.push(a as string);
  }
  return out.sort((x, y) => {
    for (const c of orders) { const d = String(x[c] ?? "").localeCompare(String(y[c] ?? "")); if (d) return d; }
    return 0;
  });
}
function fakeClient(data: Record<string, Row[]>, calls: Call[]): SupabaseClient {
  return {
    from(table: string) {
      const call: Call = { table, ops: [] };
      calls.push(call);
      const result = () => ({ data: applyOps(data[table] ?? [], call.ops), error: null });
      const builder: Record<string, unknown> = {};
      for (const m of ["select", "eq", "in", "is", "or", "order"]) {
        builder[m] = (...args: unknown[]) => { call.ops.push([m, ...args]); return builder; };
      }
      builder.range = (from: number, to: number) => {
        call.ops.push(["range", from, to]);
        const r = result();
        return Promise.resolve({ ...r, data: r.data.slice(from, to + 1) });
      };
      builder.then = (res: (v: unknown) => unknown, rej: (e: unknown) => unknown) => Promise.resolve(result()).then(res, rej);
      return builder;
    },
  } as unknown as SupabaseClient;
}

const ORG = "a5e00000-0000-4000-8000-000000000001";
const ME = "11111111-0000-4000-8000-000000000001";
const OTHER = "11111111-0000-4000-8000-000000000002";
const MY_GROUP = "22222222-0000-4000-8000-000000000001";
const OTHER_GROUP = "22222222-0000-4000-8000-000000000002";
const base = { instructions: null, due_at: null, updated_at: "2026-01-01T00:00:00Z", priority: 2, archived_at: null, org_id: ORG };
const plan = (id: string, title: string, extra: Row, created = "2026-01-01T00:00:00Z") =>
  ({ ...base, id, title, created_at: created, items: [{ kind: "room", id: "intro" }], audience: "org", personal_user_id: null, ...extra });

function world() {
  const assignments: Row[] = [
    plan("a-org", "Org-wide", {}),
    plan("a-mine", "Mine personal", { audience: "targeted", personal_user_id: ME }),
    plan("a-other", "Other's personal", { audience: "targeted", personal_user_id: OTHER }),
    plan("a-grp", "My group", { audience: "targeted", items: [{ kind: "quiz", id: "mitre" }] }),
    plan("a-oth-grp", "Other group", { audience: "targeted" }),
    plan("a-arch", "Archived", { archived_at: "2026-02-01T00:00:00Z" }),
  ];
  // 1500 unrelated target rows (other users) — more than one PostgREST page —
  // plus the two that concern this learner / their group.
  const assignment_targets: Row[] = Array.from({ length: 1500 }, (_, i) => ({
    id: `t-${String(i).padStart(5, "0")}`, org_id: ORG, assignment_id: "a-oth-grp", group_id: null, user_id: `u-${i}`,
  }));
  assignment_targets.push({ id: "t-zz-grp", org_id: ORG, assignment_id: "a-grp", group_id: MY_GROUP, user_id: null });
  assignment_targets.push({ id: "t-zz-oth", org_id: ORG, assignment_id: "a-oth-grp", group_id: OTHER_GROUP, user_id: null });
  return {
    assignments,
    assignment_targets,
    org_group_members: [{ org_id: ORG, group_id: MY_GROUP, user_id: ME }, { org_id: ORG, group_id: OTHER_GROUP, user_id: OTHER }],
    org_groups: [{ id: MY_GROUP, org_id: ORG, name: "Tier-1" }, { id: OTHER_GROUP, org_id: ORG, name: "Tier-2" }],
    room_progress: [
      { user_id: ME, room_id: "intro", completed_at: "2026-01-02T00:00:00Z", org_id: "old-org" }, // earned in ANOTHER org
    ],
    quiz_progress: [{ user_id: ME, quiz_slug: "mitre", passed: false, org_id: ORG }],
    scenario_history: [], lesson_progress: [],
  };
}

describe("loadLearnerPlans", () => {
  it("returns only the learner's plans, narrowed in SQL", async () => {
    const calls: Call[] = [];
    const plans = await loadLearnerPlans(fakeClient(world(), calls), ORG, ME, "self");
    expect(plans[0].title).toBe("Mine personal"); // personal plan first
    expect(plans.map(p => p.title).sort()).toEqual(["Mine personal", "My group", "Org-wide"]);
    expect(plans.find(p => p.title === "My group")!.via).toEqual(["Tier-1"]);

    const a = calls.find(c => c.table === "assignments")!;
    // Other learners' personal plans are excluded by the query itself, in a stable order.
    expect(a.ops).toContainEqual(["or", `personal_user_id.is.null,personal_user_id.eq.${ME}`]);
    expect(a.ops.filter(o => o[0] === "order").length).toBeGreaterThan(0);

    const t = calls.filter(c => c.table === "assignment_targets");
    expect(t.length).toBeGreaterThan(0);
    for (const c of t) {
      // Targets are fetched by WHO (user or their groups), never by a long assignment-id list.
      expect(c.ops).toContainEqual(["or", `user_id.eq.${ME},group_id.in.(${MY_GROUP})`]);
      expect(c.ops.some(o => o[0] === "in" && o[1] === "assignment_id")).toBe(false);
      expect(c.ops.some(o => o[0] === "order")).toBe(true);
    }
  });

  it('"self" counts the learner\'s progress from any org; "org" pins it to this org', async () => {
    const selfCalls: Call[] = [];
    const self = await loadLearnerPlans(fakeClient(world(), selfCalls), ORG, ME, "self");
    expect(self.find(p => p.title === "Org-wide")!.items[0].status).toBe("done");
    const selfRooms = selfCalls.find(c => c.table === "room_progress")!;
    expect(selfRooms.ops.some(o => o[0] === "eq" && o[1] === "org_id")).toBe(false);
    expect(selfRooms.ops).toContainEqual(["eq", "user_id", ME]);

    const orgCalls: Call[] = [];
    const org = await loadLearnerPlans(fakeClient(world(), orgCalls), ORG, ME, "org");
    expect(org.find(p => p.title === "Org-wide")!.items[0].status).toBe("not_started");
    expect(orgCalls.find(c => c.table === "room_progress")!.ops).toContainEqual(["eq", "org_id", ORG]);
  });

  it("rejects a non-uuid user id before building any filter string", async () => {
    await expect(loadLearnerPlans(fakeClient(world(), []), ORG, "x,personal_user_id.not.is.null", "self")).rejects.toBeInstanceOf(PlanDataError);
  });
});

describe("loadProgress (staff matrix)", () => {
  it("reads only the kinds/ids the plans use, for the given users, org-pinned and ordered", async () => {
    const calls: Call[] = [];
    const idx = await loadProgress(fakeClient(world(), calls), {
      orgId: ORG, userIds: [ME, OTHER], items: [{ kind: "quiz", id: "mitre" }],
    });
    expect(calls.map(c => c.table)).toEqual(["quiz_progress"]); // no room/scenario/lesson reads
    const q = calls[0];
    expect(q.ops).toContainEqual(["eq", "org_id", ORG]);
    expect(q.ops).toContainEqual(["in", "quiz_slug", ["mitre"]]);
    expect(q.ops).toContainEqual(["in", "user_id", [ME, OTHER]]);
    expect(q.ops.filter(o => o[0] === "order").map(o => o[1])).toEqual(["user_id", "quiz_slug"]);
    expect(idx.get(ME)?.get("quiz:mitre")).toBe("in_progress");
  });

  it("an empty item list or user list reads nothing", async () => {
    const calls: Call[] = [];
    await loadProgress(fakeClient(world(), calls), { orgId: ORG, userIds: [ME], items: [] });
    await loadProgress(fakeClient(world(), calls), { orgId: ORG, userIds: [], items: [{ kind: "room", id: "intro" }] });
    expect(calls).toHaveLength(0);
  });

  it("refuses an unpinned read without explicit users", async () => {
    await expect(loadProgress(fakeClient(world(), []), { orgId: null })).rejects.toBeInstanceOf(PlanDataError);
  });
});

describe("fetchAll / errors", () => {
  it("pages until a short page", async () => {
    const rows = Array.from({ length: 2345 }, (_, i) => ({ i }));
    const got = await fetchAll((f, t) => Promise.resolve({ data: rows.slice(f, t + 1), error: null }), "t");
    expect(got).toHaveLength(2345);
  });

  it("fails loudly when the cap is reached instead of truncating", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const full = Array.from({ length: 1000 }, (_, i) => ({ i }));
    await expect(fetchAll(() => Promise.resolve({ data: full, error: null }), "big", 2000))
      .rejects.toMatchObject({ kind: "cap" });
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it("classifies a missing 0075 column/table as a schema error", () => {
    expect(toPlanDataError({ message: "column assignments.audience does not exist", code: "42703" }, "x").kind).toBe("schema");
    expect(toPlanDataError({ message: "relation not found", code: "PGRST205" }, "x").kind).toBe("schema");
    expect(toPlanDataError({ message: "timeout", code: "57014" }, "x").kind).toBe("db");
  });
});
