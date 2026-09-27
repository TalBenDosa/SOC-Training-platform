import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { __resetNotificationsStore, attach, getSnapshot, markRead, refresh } from "./store";
import type { NotificationItem, NotificationsResponse } from "./types";

const item = (id: string, read_at: string | null = null): NotificationItem => ({
  id, kind: "plan_assigned", title: id, body: null, link: "/learn", assignment_id: null,
  created_at: "2026-09-20T10:00:00Z", read_at,
});

function mockFetch(resp: NotificationsResponse) {
  const fn = vi.fn(async (url: string) => ({
    ok: true,
    json: async () => (url === "/api/notifications" ? resp : { ok: true }),
  }));
  vi.stubGlobal("fetch", fn);
  return fn;
}

const inboxCalls = (fn: ReturnType<typeof mockFetch>) => fn.mock.calls.filter(c => c[0] === "/api/notifications").length;

beforeEach(() => __resetNotificationsStore());
afterEach(() => { __resetNotificationsStore(); vi.unstubAllGlobals(); });

describe("shared notifications store", () => {
  it("serves several consumers (bell + popup) from ONE request", async () => {
    const fn = mockFetch({ enabled: true, notifications: [item("a")], unread: 1 });
    const d1 = attach("u1");
    const d2 = attach("u1");
    await refresh(); // joins the in-flight request
    expect(inboxCalls(fn)).toBe(1);
    expect(getSnapshot().items.map(i => i.id)).toEqual(["a"]);
    // a remount within the reuse window doesn't refetch
    d2();
    const d3 = attach("u1");
    expect(inboxCalls(fn)).toBe(1);
    d1(); d3();
  });

  it("stops for a user the server switched off", async () => {
    const fn = mockFetch({ enabled: false, notifications: [], unread: 0 });
    const d = attach("u1");
    await refresh();
    expect(getSnapshot().offFor).toBe("u1");
    d();
    attach("u1");
    expect(inboxCalls(fn)).toBe(1);
  });

  it("marks read optimistically", async () => {
    mockFetch({ enabled: true, notifications: [item("a"), item("b")], unread: 2 });
    attach("u1");
    await refresh();
    await markRead(["a"]);
    const s = getSnapshot();
    expect(s.unread).toBe(1);
    expect(s.items.find(i => i.id === "a")?.read_at).not.toBeNull();
  });

  it("drops a response that lands after the user changed", async () => {
    let release!: () => void;
    const gate = new Promise<void>(r => { release = r; });
    vi.stubGlobal("fetch", vi.fn(async () => {
      await gate;
      return { ok: true, json: async () => ({ enabled: true, notifications: [item("old")], unread: 1 }) };
    }));
    attach("u1");
    const pending = refresh();
    attach("u2");
    release();
    await pending;
    expect(getSnapshot().userId).toBe("u2");
    expect(getSnapshot().items.find(i => i.id === "old")).toBeUndefined();
  });

  it("signing out resets the snapshot", async () => {
    mockFetch({ enabled: true, notifications: [item("a")], unread: 1 });
    attach("u1");
    await refresh();
    attach(null);
    expect(getSnapshot().userId).toBeNull();
    expect(getSnapshot().items).toEqual([]);
  });
});
