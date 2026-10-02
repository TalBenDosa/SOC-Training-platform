/**
 * QA M4: the threat-intel endpoint is no longer a whole-feed oracle — it answers only
 * the IOCs asked for (≤ 20), only those in a log the asker opened (or the team
 * escalated), within a per-player budget.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fakeAdmin, user, type Op, type Result } from "../../../_testing/fakeAdmin";
import { iocDigest } from "@/lib/edr/iocIntel";
import { parseIocQuery, IOC_QUERY_MAX } from "@/lib/team/iocTruth";

const state = {
  user: user() as ReturnType<typeof user> | null,
  clicks: [] as { event_id: string }[],
  escalated: [] as { payload: { event_id: string } }[],
  budget: true as boolean | "missing",
  seat: { role: "t1", status: "ready" } as { role: string; status: string } | null,
  rpcs: [] as string[],
};
vi.mock("server-only", () => ({}));
vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => state.user) }));

const at = "2026-10-02T10:00:00.000Z";
const feed = (id: string, ip: string, inject: string) => ({ seq: Number(inject.slice(1)), type: "feed.event", actor_id: null, role: null, occurred_at: at,
  payload: { id, inject_id: inject, ts: at, source: "firewall", vendor: "Palo Alto Networks", event_type: "net_connection", severity: "high", src_ip: "10.1.2.3", dst_ip: ip } });
const FEED = [feed("e1", "203.0.113.5", "i1"), feed("e2", "198.51.100.7", "i2")];
const INJECTS = [
  { id: "i1", channel: "feed", expected_action: { expected_verdict: "tp", incident_id: "inc1" } },
  { id: "i2", channel: "feed", expected_action: { expected_verdict: "tp", incident_id: "inc1" } },
];
const handler = (op: Op): Result => {
  if (op.table === "team_sessions") return { data: { id: "s1", org_id: "org1" } };
  if (op.table === "team_session_members") return { data: state.seat };
  if (op.table === "org_members") return { data: { status: "active", affiliation_expires_at: null } };
  if (op.table === "session_injects") return { data: INJECTS };
  if (op.table === "session_clicks") return { data: state.clicks };
  if (op.table === "session_events") {
    const type = op.filters.find(f => f[0] === "eq" && f[1] === "type")?.[2];
    return { data: type === "escalation.requested" ? state.escalated : FEED };
  }
  return { data: null };
};
vi.mock("@/lib/supabase/admin", () => ({
  getSupabaseAdminClient: () => fakeAdmin(handler, name => {
    state.rpcs.push(name);
    if (name === "team_ioc_lookup_allowed") return state.budget === "missing" ? { error: { message: "Could not find the function" } } : { data: state.budget };
    return { data: null };
  }).client,
}));

const { POST } = await import("./route");
const ask = (iocs: unknown) => POST(new Request("https://x/api/team/sessions/s1/ioc-truth", { method: "POST", body: JSON.stringify({ iocs }) }), { params: Promise.resolve({ id: "s1" }) });
const BOTH = [{ type: "ip", value: "203.0.113.5" }, { type: "ip", value: "198.51.100.7" }];
const d1 = iocDigest("ip", "203.0.113.5"), d2 = iocDigest("ip", "198.51.100.7");

beforeEach(() => { state.user = user({ id: "p1", orgRole: "student" }); state.clicks = [{ event_id: "e1" }]; state.escalated = []; state.budget = true; state.rpcs = []; state.seat = { role: "t1", status: "ready" }; });

describe("POST /ioc-truth", () => {
  it("answers only IOCs of logs the player opened; the rest are refused", async () => {
    const res = await ask(BOTH);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(Object.keys(body.entries)).toEqual([d1]);
    expect(body.entries[d1].v).toBe("malicious");
    expect(body.refused).toEqual([d2]);
  });

  it("an escalated log's IOCs are in hand for the team (Tier-2/3 work the case, not the raw row)", async () => {
    state.escalated = [{ payload: { event_id: "e2" } }];
    const body = await (await ask(BOTH)).json();
    expect(Object.keys(body.entries).sort()).toEqual([d1, d2].sort());
  });

  it("staff may ask about any fired log", async () => {
    state.user = user();
    state.clicks = [];
    const body = await (await ask(BOTH)).json();
    expect(Object.keys(body.entries).sort()).toEqual([d1, d2].sort());
  });

  it("nothing asked → 400; over the per-player budget → 429", async () => {
    expect((await ask([])).status).toBe(400);
    state.budget = false;
    const res = await ask(BOTH);
    expect(res.status).toBe(429);
    expect(state.rpcs).toContain("team_ioc_lookup_allowed");
  });

  it("before migration 0088 (no budget function) lookups still work", async () => {
    state.budget = "missing";
    expect((await ask(BOTH)).status).toBe(200);
  });

  it("a removed member (or a stranger) is refused before any lookup", async () => {
    state.seat = { role: "t1", status: "left" };
    expect((await ask(BOTH)).status).toBe(403);
    state.seat = null;
    expect((await ask(BOTH)).status).toBe(403);
    expect(state.rpcs).not.toContain("team_ioc_lookup_allowed");
  });
});

describe("parseIocQuery", () => {
  it("normalises, de-duplicates, drops junk and caps at IOC_QUERY_MAX", () => {
    const many = Array.from({ length: 40 }, (_, i) => ({ type: "ip", value: `203.0.113.${i}` }));
    expect(parseIocQuery({ iocs: many })).toHaveLength(IOC_QUERY_MAX);
    expect(parseIocQuery({ iocs: [{ type: "domain", value: "https://Evil.Example/x" }, { type: "domain", value: "evil.example" }, { type: "url", value: "a" }, { type: "ip" }, null] }))
      .toEqual([{ type: "domain", value: "evil.example" }]);
    expect(parseIocQuery(null)).toEqual([]);
  });
});
