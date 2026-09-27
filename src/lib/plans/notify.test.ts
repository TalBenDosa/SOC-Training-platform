import { describe, it, expect, vi, beforeEach } from "vitest";

// notify.ts → server.ts → catalog.ts imports the whole content corpus; none of
// it is needed here.
vi.mock("./catalog", () => ({
  getPlanCatalog: async () => ({ tree: [], index: new Map(), isKnown: () => true }),
  needsOrgCatalog: () => false,
}));
// NEVER send real email from tests.
vi.mock("@/lib/email/sendEmail", () => ({ sendEmail: vi.fn() }));

import { sendEmail } from "@/lib/email/sendEmail";
import {
  NOTIFY_LIMITS, addedItems, buildAudience, buildNotificationRows, deliverNotifications, emailRecipients,
  itemSetChanged, noticeText, planEditNotices, planRecipientIds, toTargetRows, type NoticeBatch, type NotificationInsert,
} from "./notify";
import type { SupabaseClient } from "@supabase/supabase-js";

const sendMock = vi.mocked(sendEmail);

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

// ── Delivery + email (sendEmail mocked) ──────────────────────────────────────
function fakeAdmin(opts: { insertError?: { message: string; code?: string }; emails?: { user_id: string; email: string | null }[] } = {}) {
  const inserts: NotificationInsert[][] = [];
  const rpcCalls: unknown[] = [];
  const client = {
    from(table: string) {
      if (table === "notifications") {
        return { insert: async (rows: NotificationInsert[]) => { inserts.push(rows); return { error: opts.insertError ?? null }; } };
      }
      if (table === "organizations") {
        const b = { select: () => b, eq: () => b, maybeSingle: async () => ({ data: { name: "Acme SOC" }, error: null }) };
        return b;
      }
      throw new Error(`unexpected table ${table}`);
    },
    rpc: async (fn: string, args: unknown) => { rpcCalls.push([fn, args]); return { data: opts.emails ?? [], error: null }; },
  } as unknown as SupabaseClient;
  return { client, inserts, rpcCalls };
}

const rowFor = (user_id: string, kind: NotificationInsert["kind"] = "plan_assigned"): NotificationInsert =>
  ({ org_id: ORG, user_id, kind, title: "New learning plan: <b>T</b>", body: "2 items", link: "/learn", assignment_id: null });

describe("deliverNotifications", () => {
  beforeEach(() => sendMock.mockReset());

  it("inserts one row per recipient, chunked, and offers no email job unless asked", async () => {
    const { client, inserts } = fakeAdmin();
    const ids = Array.from({ length: NOTIFY_LIMITS.insertChunk + 3 }, (_, i) => `11111111-0000-4000-8000-${String(i).padStart(12, "0")}`);
    const res = await deliverNotifications(client, {
      orgId: ORG, actorId: ADMIN, assignmentId: null, batches: [batch("plan_assigned", ids)],
      eligible: new Set(ids), email: false, origin: "https://www.hackthesoc.app",
    });
    expect(res.notified).toBe(ids.length);
    expect(inserts.map(c => c.length)).toEqual([NOTIFY_LIMITS.insertChunk, 3]);
    expect(res.emailJob).toBeNull();
    expect(sendMock).not.toHaveBeenCalled();
  });

  it("an insert failure is swallowed (the save must not fail)", async () => {
    const { client } = fakeAdmin({ insertError: { message: "relation does not exist", code: "42P01" } });
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const res = await deliverNotifications(client, {
      orgId: ORG, actorId: ADMIN, assignmentId: null, batches: [batch("plan_assigned", [S1])],
      eligible: aud.eligible, email: false, origin: "https://www.hackthesoc.app",
    });
    expect(res.notified).toBe(0);
    spy.mockRestore();
  });
});

describe("emailRecipients", () => {
  beforeEach(() => { sendMock.mockReset(); sendMock.mockResolvedValue({ ok: true }); });
  const noSleep = async () => {};

  it("sends ONE email per recipient, only to recipients (never to other members)", async () => {
    const { client, rpcCalls } = fakeAdmin({ emails: [
      { user_id: S1, email: "s1@example.test" },
      { user_id: S2, email: "s2@example.test" },
      { user_id: S3, email: "s3@example.test" },      // a member, NOT a recipient
      { user_id: ADMIN, email: "boss@example.test" }, // the actor, NOT a recipient
    ] });
    const report = await emailRecipients(client, ORG, [rowFor(S1), rowFor(S2), rowFor(S1, "plan_updated")], "https://www.hackthesoc.app", noSleep);
    expect(rpcCalls).toEqual([["org_member_emails", { p_org: ORG }]]);
    const to = sendMock.mock.calls.map(c => c[0].to);
    expect(to.sort()).toEqual(["s1@example.test", "s2@example.test"]);
    expect(report).toMatchObject({ sent: 2, failed: 0 });
    const mail = sendMock.mock.calls[0][0];
    expect(mail.html).toContain("https://www.hackthesoc.app/learn");
    expect(mail.html).not.toContain("<b>T</b>");      // manager-authored title is escaped
    expect(mail.html).toContain("&lt;b&gt;T&lt;/b&gt;");
  });

  it("skips recipients without an address and ignores rows of another org", async () => {
    const { client } = fakeAdmin({ emails: [{ user_id: S1, email: null }, { user_id: S2, email: "not-an-email" }, { user_id: S3, email: "s3@example.test" }] });
    await emailRecipients(client, ORG, [rowFor(S1), rowFor(S2), { ...rowFor(S3), org_id: "b5e00000-0000-4000-8000-000000000001" }], "https://www.hackthesoc.app", noSleep);
    expect(sendMock).not.toHaveBeenCalled();
  });

  it("stops early when email isn't configured (no RESEND_API_KEY → skipped)", async () => {
    sendMock.mockResolvedValue({ ok: false, skipped: true });
    const users = Array.from({ length: 7 }, (_, i) => `11111111-0000-4000-8000-${String(i).padStart(12, "0")}`);
    const { client } = fakeAdmin({ emails: users.map((u, i) => ({ user_id: u, email: `u${i}@example.test` })) });
    const sleep = vi.fn(async () => {});
    const report = await emailRecipients(client, ORG, users.map(u => rowFor(u)), "https://www.hackthesoc.app", sleep);
    expect(sendMock).toHaveBeenCalledTimes(NOTIFY_LIMITS.emailConcurrency);
    expect(sleep).not.toHaveBeenCalled();
    expect(report.skipped).toBe(7);
  });

  it("paces waves, caps the total, and counts failures without throwing", async () => {
    sendMock.mockImplementation(async ({ to }) => (to === "u1@example.test" ? { ok: false, error: "HTTP 500" } : { ok: true }));
    const users = Array.from({ length: NOTIFY_LIMITS.emails + 5 }, (_, i) => `11111111-0000-4000-8000-${String(i).padStart(12, "0")}`);
    const { client } = fakeAdmin({ emails: users.map((u, i) => ({ user_id: u, email: `u${i}@example.test` })) });
    const sleep = vi.fn(async () => {});
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const report = await emailRecipients(client, ORG, users.map(u => rowFor(u)), "https://www.hackthesoc.app", sleep);
    spy.mockRestore();
    expect(sendMock).toHaveBeenCalledTimes(NOTIFY_LIMITS.emails);
    expect(report).toMatchObject({ attempted: NOTIFY_LIMITS.emails, sent: NOTIFY_LIMITS.emails - 1, failed: 1, capped: 5 });
    expect(sleep).toHaveBeenCalledTimes(Math.ceil(NOTIFY_LIMITS.emails / NOTIFY_LIMITS.emailConcurrency) - 1);
  });

  it("refuses a malformed origin", async () => {
    const { client } = fakeAdmin({ emails: [{ user_id: S1, email: "s1@example.test" }] });
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    await emailRecipients(client, ORG, [rowFor(S1)], "javascript:alert(1)", noSleep);
    spy.mockRestore();
    expect(sendMock).not.toHaveBeenCalled();
  });

  it("deliverNotifications hands back an email job for exactly the notified rows", async () => {
    const { client } = fakeAdmin({ emails: [{ user_id: S1, email: "s1@example.test" }, { user_id: ADMIN, email: "boss@example.test" }] });
    const res = await deliverNotifications(client, {
      orgId: ORG, actorId: ADMIN, assignmentId: null, batches: [batch("plan_assigned", [S1, ADMIN, OUTSIDER])],
      eligible: aud.eligible, email: true, origin: "https://www.hackthesoc.app",
    });
    expect(res.notified).toBe(1);
    expect(res.emailJob).not.toBeNull();
    expect(sendMock).not.toHaveBeenCalled();         // nothing is sent until the job runs (after the response)
    await res.emailJob!();
    expect(sendMock.mock.calls.map(c => c[0].to)).toEqual(["s1@example.test"]);
  });
});
