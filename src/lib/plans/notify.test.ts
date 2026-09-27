import { describe, it, expect, vi, beforeEach } from "vitest";

// notify.ts → server.ts → catalog.ts imports the whole content corpus; none of
// it is needed here.
vi.mock("./catalog", () => ({
  getPlanCatalog: async () => ({ tree: [], index: new Map(), isKnown: () => true }),
  needsOrgCatalog: () => false,
}));
// NEVER send real email from tests: the provider layer is fully mocked.
vi.mock("@/lib/email/sendEmail", () => ({ sendEmail: vi.fn(), sendEmailBatch: vi.fn(), isEmailConfigured: vi.fn(() => true) }));
vi.mock("@/lib/security/rateLimit", () => ({ checkRateLimit: vi.fn(async () => ({ ok: true, retryAfter: 0 })) }));
// Plan emails are OFF by default in the product (shared free-tier Resend account); these
// tests exercise the email path, so enable a budget before notify.ts is evaluated.
vi.hoisted(() => { process.env.PLAN_EMAIL_DAILY_BUDGET = "50"; });

import { isEmailConfigured, sendEmailBatch } from "@/lib/email/sendEmail";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { describeNotifyOutcome, emptyEmailReport } from "@/lib/notifications/types";
import {
  NOTIFY_LIMITS, PLAN_EMAIL_DAILY_BUDGET, addedItems, buildAudience, buildNotificationRows, deliverNotifications,
  emailBudgetKey, emailRecipients, itemSetChanged, noticeText, planEditNotices, planRecipientIds, settleEmailJob,
  toTargetRows, type InsertedNotification, type NoticeBatch, type NotificationInsert,
} from "./notify";
import type { SupabaseClient } from "@supabase/supabase-js";

const batchMock = vi.mocked(sendEmailBatch);
const configuredMock = vi.mocked(isEmailConfigured);
const rateMock = vi.mocked(checkRateLimit);

const ORG = "a5e00000-0000-4000-8000-000000000001";
const ADMIN = "aaaaaaaa-0000-4000-8000-000000000001";
const S1 = "11111111-0000-4000-8000-000000000001";
const S2 = "11111111-0000-4000-8000-000000000002";
const S3 = "11111111-0000-4000-8000-000000000003";
const GONE = "11111111-0000-4000-8000-0000000000ff";     // deactivated
const INSTR = "22222222-0000-4000-8000-000000000001";
const OUTSIDER = "99999999-0000-4000-8000-000000000001";  // another org entirely
const G1 = "99990000-0000-4000-8000-000000000001";
const G2 = "99990000-0000-4000-8000-000000000002";

const members = [
  { user_id: ADMIN, role: "org_admin", status: "active" },
  { user_id: S1, role: "student", status: "active" },
  { user_id: S2, role: "student", status: "active" },
  { user_id: S3, role: "student", status: "active" },
  { user_id: GONE, role: "student", status: "removed" },
  { user_id: INSTR, role: "instructor", status: "active" },
];
const groupRows = [
  { group_id: G1, user_id: S1 }, { group_id: G1, user_id: S2 }, { group_id: G1, user_id: GONE },
  { group_id: G2, user_id: S2 }, { group_id: G2, user_id: INSTR },
];
const aud = buildAudience(members, groupRows);

// ── Recipient resolution ─────────────────────────────────────────────────────
describe("planRecipientIds", () => {
  it("org-wide → the org's ACTIVE students only (no staff, no removed members)", () => {
    expect(planRecipientIds({ audience: "org", personal_user_id: null }, [], aud)).toEqual([S1, S2, S3].sort());
  });

  it("targeted → group members ∪ direct users, deduped, inactive dropped", () => {
    const targets = toTargetRows({ group_ids: [G1, G2], user_ids: [S2, S3, GONE] });
    expect(planRecipientIds({ audience: "targeted", personal_user_id: null }, targets, aud)).toEqual([INSTR, S1, S2, S3].sort());
  });

  it("targeted at an unknown group or a non-member reaches nobody", () => {
    const targets = toTargetRows({ group_ids: ["99990000-0000-4000-8000-0000000000aa"], user_ids: [OUTSIDER] });
    expect(planRecipientIds({ audience: "targeted", personal_user_id: null }, targets, aud)).toEqual([]);
  });

  it("personal → only its owner (and only while active)", () => {
    expect(planRecipientIds({ audience: "targeted", personal_user_id: S3 }, [], aud)).toEqual([S3]);
    expect(planRecipientIds({ audience: "targeted", personal_user_id: GONE }, [], aud)).toEqual([]);
  });

  it("an archived plan reaches nobody", () => {
    expect(planRecipientIds({ audience: "org", personal_user_id: null, archived_at: "2026-09-01T00:00:00Z" }, [], aud)).toEqual([]);
  });

  it("buildAudience dedupes repeated membership rows", () => {
    const a = buildAudience(members, [...groupRows, { group_id: G1, user_id: S1 }]);
    expect(a.groupMembers.get(G1)).toEqual([S1, S2, GONE]);
  });
});

// ── Rows: dedupe, actor, eligibility, cap ────────────────────────────────────
const batch = (kind: NoticeBatch["kind"], userIds: string[], link = "/learn"): NoticeBatch =>
  ({ kind, userIds, title: `t-${kind}`, body: "b", link });

describe("buildNotificationRows", () => {
  const ctx = { orgId: ORG, actorId: ADMIN, assignmentId: null, eligible: aud.eligible };

  it("one row per person — the first batch wins (assigned beats updated)", () => {
    const { rows } = buildNotificationRows([batch("plan_assigned", [S1, S2, S1]), batch("plan_updated", [S2, S3])], ctx);
    expect(rows.map(r => [r.user_id, r.kind])).toEqual([[S1, "plan_assigned"], [S2, "plan_assigned"], [S3, "plan_updated"]]);
  });

  it("never notifies the actor, an inactive member or a non-member", () => {
    const { rows } = buildNotificationRows([batch("plan_assigned", [ADMIN, GONE, OUTSIDER, S1])], ctx);
    expect(rows.map(r => r.user_id)).toEqual([S1]);
  });

  it("caps the batch and reports how many were dropped", () => {
    const { rows, dropped } = buildNotificationRows([batch("plan_assigned", [S1, S2, S3])], { ...ctx, cap: 2 });
    expect(rows).toHaveLength(2);
    expect(dropped).toBe(1);
  });

  it("stamps org + plan and replaces an unsafe link with /learn", () => {
    const { rows } = buildNotificationRows(
      [batch("plan_assigned", [S1], "//evil.example/x"), batch("plan_updated", [S2], "https://evil.example")],
      { ...ctx, assignmentId: "bbbbbbbb-0000-4000-8000-000000000001" },
    );
    expect(rows.every(r => r.org_id === ORG && r.assignment_id === "bbbbbbbb-0000-4000-8000-000000000001")).toBe(true);
    expect(rows.map(r => r.link)).toEqual(["/learn", "/learn"]);
  });
});

// ── Edit diff ────────────────────────────────────────────────────────────────
describe("planEditNotices (new recipients vs updated)", () => {
  it("new recipients get 'assigned'; existing ones get 'updated' only when items were added", () => {
    expect(planEditNotices([S1, S2], [S1, S2, S3], 2)).toEqual({ assigned: [S3], updated: [S1, S2] });
    expect(planEditNotices([S1, S2], [S1, S2, S3], 0)).toEqual({ assigned: [S3], updated: [] });
  });

  it("removed recipients get nothing; no change → nothing", () => {
    expect(planEditNotices([S1, S2, S3], [S1], 0)).toEqual({ assigned: [], updated: [] });
    expect(planEditNotices([S1, S2], [S1, S2], 0)).toEqual({ assigned: [], updated: [] });
  });

  it("switching org-wide → a group notifies only people who didn't already have it", () => {
    const before = planRecipientIds({ audience: "org", personal_user_id: null }, [], aud);                        // S1 S2 S3
    const after = planRecipientIds({ audience: "targeted", personal_user_id: null }, toTargetRows({ group_ids: [G2], user_ids: [] }), aud); // S2 INSTR
    expect(planEditNotices(before, after, 0)).toEqual({ assigned: [INSTR], updated: [] });
  });

  it("addedItems / itemSetChanged compare by kind:id, ignoring order, notes and priority", () => {
    const a = [{ kind: "room" as const, id: "intro" }, { kind: "quiz" as const, id: "mitre" }];
    const reordered = [{ kind: "quiz" as const, id: "mitre", note: "x" }, { kind: "room" as const, id: "intro", priority: 1 as const }];
    expect(itemSetChanged(a, reordered)).toBe(false);
    expect(addedItems(a, reordered)).toEqual([]);
    const grown = [...a, { kind: "lesson" as const, id: "soc--intro" }];
    expect(addedItems(a, grown)).toEqual([{ kind: "lesson", id: "soc--intro" }]);
    expect(itemSetChanged(a, grown)).toBe(true);
    expect(itemSetChanged(a, [a[0]])).toBe(true);               // a removal also counts
    expect(itemSetChanged([], a)).toBe(true);                    // first personal plan
    expect(itemSetChanged(a, [a[0], { kind: "room", id: "other" }])).toBe(true); // swap, same size
  });
});

// ── Text ─────────────────────────────────────────────────────────────────────
describe("noticeText", () => {
  it("links a single item directly, anything else to /learn", () => {
    expect(noticeText("plan_assigned", { title: "T1", due_at: null }, [{ title: "Intro", href: "/rooms/intro" }]).link).toBe("/rooms/intro");
    expect(noticeText("plan_assigned", { title: "T1", due_at: null }, [{ title: "A", href: "/a" }, { title: "B", href: "/b" }]).link).toBe("/learn");
  });

  it("describes the plan, due date and first titles", () => {
    const t = noticeText("plan_updated", { title: "Tier-1", due_at: "2026-10-01T23:59:59.999Z" },
      [{ title: "A" }, { title: "B" }, { title: "C" }, { title: "D" }]);
    expect(t.title).toBe("Learning plan updated: Tier-1");
    expect(t.body).toBe("4 new items added · due 01 Oct 2026 — A, B, C +1 more");
    expect(noticeText("personal_plan", { title: "x", due_at: null }, [{ title: "A" }]).title).toBe("Your personal priorities were updated");
  });

  it("clips to the DB limits", () => {
    const t = noticeText("plan_assigned", { title: "x".repeat(400), due_at: null }, Array.from({ length: 3 }, () => ({ title: "y".repeat(400) })));
    expect(t.title.length).toBeLessThanOrEqual(200);
    expect(t.body.length).toBeLessThanOrEqual(500);
  });
});

// ── Delivery + email (email sender + rate-limit store mocked) ────────────────
type Op = [string, ...unknown[]];
interface Call { table: string; ops: Op[] }

function fakeAdmin(opts: {
  /** Per insert call (by index): an error to return instead of success. */
  insertErrors?: Record<number, { message: string; code?: string }>;
  /** Rows the dedupe lookup should report as already emailed. */
  emailedBefore?: { assignment_id: string; user_id: string }[];
  /** What plan_recipient_emails returns (the fake does NOT filter — the code must). */
  emails?: { user_id: string; email: string | null }[];
} = {}) {
  const calls: Call[] = [];
  const inserts: NotificationInsert[][] = [];
  const updates: { patch: unknown; ids: string[] }[] = [];
  const rpcCalls: [string, unknown][] = [];
  let nextId = 0;
  const client = {
    from(table: string) {
      const call: Call = { table, ops: [] };
      calls.push(call);
      const b: Record<string, unknown> = {};
      for (const m of ["select", "eq", "in", "gte", "limit"]) {
        b[m] = (...a: unknown[]) => { call.ops.push([m, ...a]); return b; };
      }
      b.insert = (rows: NotificationInsert[]) => {
        const idx = inserts.length;
        inserts.push(rows);
        return {
          select: async () => {
            const err = opts.insertErrors?.[idx];
            if (err) return { data: null, error: err };
            return { data: rows.map(r => ({ id: `n-${nextId++}`, user_id: r.user_id })), error: null };
          },
        };
      };
      b.update = (patch: unknown) => {
        const u = { patch, ids: [] as string[] };
        updates.push(u);
        const ub: Record<string, unknown> = {
          eq: () => ub,
          in: async (_c: string, ids: string[]) => { u.ids = ids; return { error: null }; },
        };
        return ub;
      };
      b.maybeSingle = async () => ({ data: table === "organizations" ? { name: "Acme SOC" } : null, error: null });
      b.then = (res: (v: unknown) => unknown, rej: (e: unknown) => unknown) => {
        // The dedupe lookup: notifications … eq(assignment_id) in(user_id) gte(emailed_at)
        const plan = call.ops.find(o => o[0] === "eq" && o[1] === "assignment_id")?.[2];
        const users = (call.ops.find(o => o[0] === "in" && o[1] === "user_id")?.[2] ?? []) as string[];
        const data = (opts.emailedBefore ?? []).filter(r => r.assignment_id === plan && users.includes(r.user_id)).map(r => ({ user_id: r.user_id }));
        return Promise.resolve({ data, error: null }).then(res, rej);
      };
      return b;
    },
    rpc: async (fn: string, args: unknown) => { rpcCalls.push([fn, args]); return { data: opts.emails ?? [], error: null }; },
  } as unknown as SupabaseClient;
  return { client, calls, inserts, updates, rpcCalls };
}

const PLAN = "bbbbbbbb-0000-4000-8000-000000000001";
const ORIGIN = "https://www.hackthesoc.app";
const row = (user_id: string, id = `n-${user_id.slice(-4)}`, kind: NotificationInsert["kind"] = "plan_assigned"): InsertedNotification =>
  ({ id, org_id: ORG, user_id, kind, title: "New learning plan: T", body: "2 items — Secret item title", link: "/learn", assignment_id: PLAN });
const uid = (i: number) => `11111111-0000-4000-8000-${String(i).padStart(12, "0")}`;
const deliver = (client: SupabaseClient, over: Partial<Parameters<typeof deliverNotifications>[1]> = {}) =>
  deliverNotifications(client, {
    orgId: ORG, actorId: ADMIN, assignmentId: PLAN, batches: [batch("plan_assigned", [S1, S2])],
    eligible: aud.eligible, email: false, origin: ORIGIN, planTitle: "Tier-1 onboarding", ...over,
  });

describe("deliverNotifications", () => {
  beforeEach(() => { batchMock.mockReset(); configuredMock.mockReturnValue(true); });

  it("inserts one row per recipient in chunks and returns the rows actually written", async () => {
    const { client, inserts } = fakeAdmin();
    const ids = Array.from({ length: NOTIFY_LIMITS.insertChunk + 3 }, (_, i) => uid(i));
    const res = await deliver(client, { batches: [batch("plan_assigned", ids)], eligible: new Set(ids) });
    expect(res.notified).toBe(ids.length);
    expect(res.inserted.every(r => typeof r.id === "string")).toBe(true);
    expect(inserts.map(c => c.length)).toEqual([NOTIFY_LIMITS.insertChunk, 3]);
    expect(res.emailJob).toBeNull();                       // email not requested
  });

  it("a failed chunk is skipped, the NEXT chunk still goes, and only written rows can be emailed", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { client } = fakeAdmin({ insertErrors: { 0: { message: "violates foreign key", code: "23503" } } });
    const ids = Array.from({ length: NOTIFY_LIMITS.insertChunk + 2 }, (_, i) => uid(i));
    const res = await deliver(client, { batches: [batch("plan_assigned", ids)], eligible: new Set(ids), email: true });
    spy.mockRestore();
    expect(res.notified).toBe(2);
    expect(res.inserted.map(r => r.user_id)).toEqual(ids.slice(NOTIFY_LIMITS.insertChunk));
    expect(res.emailJob).not.toBeNull();
  });

  it("table missing (code ahead of 0076) → nothing written and NO email job", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { client, inserts } = fakeAdmin({ insertErrors: { 0: { message: "relation does not exist", code: "42P01" } } });
    const res = await deliver(client, { email: true });
    spy.mockRestore();
    expect(res).toMatchObject({ notified: 0, tableMissing: true, emailJob: null });
    expect(inserts).toHaveLength(1);                       // stops at the first missing-table error
  });

  it("the email job covers exactly the written rows (actor / non-members never)", async () => {
    batchMock.mockImplementation(async msgs => ({ skipped: false, sent: msgs.map(() => true), errors: [] }));
    const { client } = fakeAdmin({ emails: [{ user_id: S1, email: "s1@example.test" }, { user_id: ADMIN, email: "boss@example.test" }, { user_id: S3, email: "s3@example.test" }] });
    const res = await deliver(client, { batches: [batch("plan_assigned", [S1, ADMIN, OUTSIDER])], email: true });
    expect(res.notified).toBe(1);
    expect(batchMock).not.toHaveBeenCalled();              // nothing is sent until the job runs
    const rep = await res.emailJob!();
    expect(batchMock.mock.calls[0][0].map(m => m.to)).toEqual(["s1@example.test"]);
    expect(rep).toMatchObject({ considered: 1, emailed: 1, failed: 0 });
  });
});

describe("emailRecipients", () => {
  beforeEach(() => {
    batchMock.mockReset();
    batchMock.mockImplementation(async msgs => ({ skipped: false, sent: msgs.map(() => true), errors: [] }));
    configuredMock.mockReturnValue(true);
    rateMock.mockReset();
    rateMock.mockResolvedValue({ ok: true, retryAfter: 0 });
  });

  it("ONE batch call, one message per recipient, only to recipients; stamps emailed_at on those rows", async () => {
    const { client, rpcCalls, updates } = fakeAdmin({ emails: [
      { user_id: S1, email: "s1@example.test" }, { user_id: S2, email: "s2@example.test" },
      { user_id: S3, email: "s3@example.test" },           // a member, NOT a recipient
    ] });
    const rep = await emailRecipients(client, ORG, [row(S1, "n1"), row(S2, "n2"), row(S1, "n1b", "plan_updated")], { origin: ORIGIN, planTitle: "Tier-1" });
    expect(rpcCalls).toEqual([["plan_recipient_emails", { p_org: ORG, p_users: [S1, S2] }]]);
    expect(batchMock).toHaveBeenCalledTimes(1);
    expect(batchMock.mock.calls[0][0].map(m => m.to)).toEqual(["s1@example.test", "s2@example.test"]);
    expect(rep).toMatchObject({ considered: 2, emailed: 2, failed: 0 });
    expect(updates).toHaveLength(1);
    expect(updates[0].ids).toEqual(["n1", "n2"]);
    expect((updates[0].patch as { emailed_at: string }).emailed_at).toMatch(/^\d{4}-/);
  });

  it("email content: fixed subject, escaped + clipped plan title, no item titles", async () => {
    const { client } = fakeAdmin({ emails: [{ user_id: S1, email: "s1@example.test" }] });
    await emailRecipients(client, ORG, [row(S1)], { origin: ORIGIN, planTitle: `<script>x</script> ${"long ".repeat(40)}` });
    const m = batchMock.mock.calls[0][0][0];
    expect(m.subject).toBe("New learning plan from Acme SOC");
    expect(m.html).not.toContain("<script>");
    expect(m.html).toContain("&lt;script&gt;");
    expect(m.html).not.toContain("Secret item title");
    expect(m.text).not.toContain("Secret item title");
    expect(m.html).toContain(`${ORIGIN}/learn`);
  });

  it("24 h dedupe: someone already emailed about this plan is skipped", async () => {
    const { client } = fakeAdmin({
      emailedBefore: [{ assignment_id: PLAN, user_id: S1 }],
      emails: [{ user_id: S1, email: "s1@example.test" }, { user_id: S2, email: "s2@example.test" }],
    });
    const rep = await emailRecipients(client, ORG, [row(S1), row(S2)], { origin: ORIGIN, planTitle: "T" });
    expect(batchMock.mock.calls[0][0].map(m => m.to)).toEqual(["s2@example.test"]);
    expect(rep.skipped.dedupe).toBe(1);
    expect(rep.emailed).toBe(1);
  });

  it("daily budget: once the org's budget is spent, the rest are skipped (in-app unaffected)", async () => {
    let n = 0;
    rateMock.mockImplementation(async () => ({ ok: ++n <= 2, retryAfter: n <= 2 ? 0 : 3600 }));
    const users = [S1, S2, S3];
    const { client } = fakeAdmin({ emails: users.map((u, i) => ({ user_id: u, email: `u${i}@example.test` })) });
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const rep = await emailRecipients(client, ORG, users.map(u => row(u)), { origin: ORIGIN, planTitle: "T" });
    spy.mockRestore();
    expect(rep).toMatchObject({ emailed: 2, skipped: { budget: 1 } });
    expect(batchMock.mock.calls[0][0]).toHaveLength(2);
    expect(rateMock.mock.calls[0][0]).toBe(emailBudgetKey(ORG));
    expect(rateMock.mock.calls[0][1]).toBe(PLAN_EMAIL_DAILY_BUDGET);
  });

  it("not configured → skipped as unconfigured, no budget spent, no address lookup, no send", async () => {
    configuredMock.mockReturnValue(false);
    const { client, rpcCalls } = fakeAdmin({ emails: [{ user_id: S1, email: "s1@example.test" }] });
    const rep = await emailRecipients(client, ORG, [row(S1), row(S2)], { origin: ORIGIN, planTitle: "T" });
    expect(rep.skipped.unconfigured).toBe(2);
    expect(rateMock).not.toHaveBeenCalled();
    expect(rpcCalls).toEqual([]);
    expect(batchMock).not.toHaveBeenCalled();
  });

  it("no address / invalid address / another org's row → skipped, never sent", async () => {
    const { client } = fakeAdmin({ emails: [{ user_id: S1, email: null }, { user_id: S2, email: "not-an-email" }, { user_id: S3, email: "s3@example.test" }] });
    const rep = await emailRecipients(client, ORG, [row(S1), row(S2), { ...row(S3), org_id: "b5e00000-0000-4000-8000-000000000001" }], { origin: ORIGIN, planTitle: "T" });
    expect(rep).toMatchObject({ considered: 2, emailed: 0, skipped: { no_address: 2 } });
    expect(batchMock).not.toHaveBeenCalled();
  });

  it("caps a save at NOTIFY_LIMITS.emails and reports provider failures without throwing", async () => {
    batchMock.mockImplementation(async msgs => ({ skipped: false, sent: msgs.map((_: unknown, i: number) => i !== 0), errors: ["HTTP 500"] }));
    const users = Array.from({ length: NOTIFY_LIMITS.emails + 5 }, (_, i) => uid(i));
    const { client, updates } = fakeAdmin({ emails: users.map((u, i) => ({ user_id: u, email: `u${i}@example.test` })) });
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const rep = await emailRecipients(client, ORG, users.map((u, i) => row(u, `n${i}`)), { origin: ORIGIN, planTitle: "T" });
    spy.mockRestore();
    expect(batchMock.mock.calls[0][0]).toHaveLength(NOTIFY_LIMITS.emails);
    expect(rep).toMatchObject({ emailed: NOTIFY_LIMITS.emails - 1, failed: 1, skipped: { cap: 5 } });
    expect(updates[0].ids).not.toContain("n0");            // the failed one isn't marked emailed
  });

  it("refuses a malformed origin", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const { client } = fakeAdmin({ emails: [{ user_id: S1, email: "s1@example.test" }] });
    await emailRecipients(client, ORG, [row(S1)], { origin: "javascript:alert(1)", planTitle: "T" });
    spy.mockRestore();
    expect(batchMock).not.toHaveBeenCalled();
  });
});

describe("settleEmailJob", () => {
  const report = { ...emptyEmailReport(2), emailed: 2 };

  it("returns the real report when the job finishes in time", async () => {
    const schedule = vi.fn();
    const r = await settleEmailJob(async () => report, schedule, vi.fn(), 2, 1_000);
    expect(r).toEqual(report);
    expect(schedule).not.toHaveBeenCalled();
  });

  it("a slow job is handed to after() (same promise, runs to completion) and audited late", async () => {
    let finish!: (r: typeof report) => void;
    const job = () => new Promise<typeof report>(res => { finish = res; });
    const tasks: (() => Promise<unknown>)[] = [];
    const onLate = vi.fn();
    const r = await settleEmailJob(job, t => { tasks.push(t); }, onLate, 2, 5);
    expect(r).toMatchObject({ pending: true, considered: 2 });
    expect(tasks).toHaveLength(1);
    const done = tasks[0]();
    finish(report);
    await done;
    expect(onLate).toHaveBeenCalledWith(report);
  });
});

describe("describeNotifyOutcome", () => {
  it("summarises notified / emailed / skipped reasons", () => {
    expect(describeNotifyOutcome({ notified: 3, email: null })).toBe("3 learners notified");
    expect(describeNotifyOutcome({ notified: 3, email: { ...emptyEmailReport(3), emailed: 3 } })).toBe("3 learners notified · 3 emailed");
    expect(describeNotifyOutcome({ notified: 3, email: { ...emptyEmailReport(3), skipped: { budget: 3, dedupe: 0, unconfigured: 0, no_address: 0, cap: 0 } } }))
      .toBe("3 learners notified · emails skipped: daily email limit reached (3)");
    expect(describeNotifyOutcome({ notified: 1, email: { ...emptyEmailReport(1), skipped: { budget: 0, dedupe: 0, unconfigured: 1, no_address: 0, cap: 0 } } }))
      .toBe("1 learner notified · emails skipped: email not configured");
    expect(describeNotifyOutcome({ notified: 2, email: { ...emptyEmailReport(2), emailed: 1, failed: 1 } })).toBe("2 learners notified · 1 emailed · 1 email failed");
    expect(describeNotifyOutcome({ notified: 2, email: { ...emptyEmailReport(2), pending: true } })).toBe("2 learners notified · emails sending");
    expect(describeNotifyOutcome({ notified: 0, email: null })).toBe("");
    expect(describeNotifyOutcome(null)).toBe("");
  });
});

describe("plan emails default", () => {
  it("are OFF unless PLAN_EMAIL_DAILY_BUDGET is set (in-app notifications are unaffected)", async () => {
    const prev = process.env.PLAN_EMAIL_DAILY_BUDGET;
    delete process.env.PLAN_EMAIL_DAILY_BUDGET;
    vi.resetModules();
    const fresh = await import("./notify");
    expect(fresh.PLAN_EMAIL_DAILY_BUDGET).toBe(0);
    expect(fresh.planEmailsEnabled()).toBe(false);
    process.env.PLAN_EMAIL_DAILY_BUDGET = prev;
    vi.resetModules();
  });
});
