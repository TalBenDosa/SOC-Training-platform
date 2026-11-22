// Room-film playback telemetry (migration 0117): signed-in learners only, validated and capped,
// rate-limited per learner, and silent (204) when the table is not deployed yet.
import { describe, it, expect, vi, beforeEach } from "vitest";

let authed: { id: string; orgId: string | null } | null = { id: "11111111-1111-4111-8111-111111111111", orgId: "22222222-2222-4222-8222-222222222222" };
vi.mock("@/lib/auth/apiGuard", () => ({ getAuthedUser: vi.fn(async () => authed) }));

const inserts: Record<string, unknown>[] = [];
let recent = 0;
let missingTable = false;
const admin = {
  from() {
    const q = {
      select() { return q; }, eq() { return q; },
      gte: async () => missingTable ? { count: null, error: { code: "42P01", message: "relation does not exist" } } : { count: recent, error: null },
      insert: async (row: Record<string, unknown>) => { inserts.push(row); return { error: null }; },
    };
    return q;
  },
};
vi.mock("@/lib/supabase/admin", () => ({ getSupabaseAdminClient: () => admin }));

const { POST } = await import("./route");
const { filmPath, FILM_EVENTS_PER_HOUR } = await import("@/lib/media/filmEvent");
const FILM = "https://wrxhxtdllbctsawvewue.supabase.co/storage/v1/object/public/lesson-videos/operation/malware-analysis-fundamentals/detonation-intro-51bdb266.mp4";
const post = (body: unknown) => POST(new Request("https://x/api/media/film-event", { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body) }));

beforeEach(() => { authed = { id: "11111111-1111-4111-8111-111111111111", orgId: "22222222-2222-4222-8222-222222222222" }; inserts.length = 0; recent = 0; missingTable = false; });

describe("POST /api/media/film-event", () => {
  it("records a stall recovery with the bucket path, the learner and their org", async () => {
    const res = await post({ kind: "recovered", src: FILM, roomId: "malware-analysis-fundamentals", clipKey: "intro", waitMs: 4200.7, positionS: 12.3, durationS: 51.3, netType: "4g", downlinkMbps: 3.5 });
    expect(res.status).toBe(204);
    expect(inserts[0]).toMatchObject({
      user_id: authed!.id, org_id: authed!.orgId, kind: "recovered", wait_ms: 4201,
      src_path: "operation/malware-analysis-fundamentals/detonation-intro-51bdb266.mp4",
      room_id: "malware-analysis-fundamentals", clip_key: "intro", net_type: "4g",
    });
  });

  it("guests are not recorded", async () => {
    authed = null;
    expect((await post({ kind: "start", src: FILM })).status).toBe(204);
    expect(inserts).toHaveLength(0);
  });

  it("rejects an unknown kind, a foreign URL and junk", async () => {
    expect((await post({ kind: "hack", src: FILM })).status).toBe(400);
    expect((await post({ kind: "start", src: "https://evil.test/x.mp4" })).status).toBe(400);
    expect((await post("not json")).status).toBe(400);
    expect((await post("x".repeat(3000))).status).toBe(413);
    expect(inserts).toHaveLength(0);
  });

  it("drops bad identifiers and clamps numbers instead of storing them", async () => {
    await post({ kind: "stall", src: FILM, roomId: "<script>", clipKey: "a b", waitMs: 99, positionS: -4, downlinkMbps: 1e9, netType: "drop table" });
    expect(inserts[0]).toMatchObject({ room_id: null, clip_key: null, wait_ms: null, position_s: null, downlink_mbps: 100000, net_type: null });
  });

  it("stops recording past the hourly cap", async () => {
    recent = FILM_EVENTS_PER_HOUR;
    expect((await post({ kind: "start", src: FILM })).status).toBe(204);
    expect(inserts).toHaveLength(0);
  });

  it("answers 204 before the migration is deployed", async () => {
    missingTable = true;
    expect((await post({ kind: "start", src: FILM })).status).toBe(204);
    expect(inserts).toHaveLength(0);
  });
});

describe("filmPath", () => {
  it("keeps the bucket object path or a same-origin path, nothing else", () => {
    expect(filmPath(FILM + "?t=1")).toBe("operation/malware-analysis-fundamentals/detonation-intro-51bdb266.mp4");
    expect(filmPath("/lesson-videos/x/y.mp4")).toBe("/lesson-videos/x/y.mp4");
    expect(filmPath("//evil.test/x.mp4")).toBeNull();
    expect(filmPath("/a/../b.mp4")).toBeNull();
    expect(filmPath(42)).toBeNull();
  });
});
