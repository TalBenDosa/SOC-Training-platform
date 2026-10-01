// QA phase 7, E-08: an Upstash outage degrades to per-instance limits (logged),
// never "allow everything" — the email-cost ceilings depend on these counters.
import { describe, it, expect, vi, afterEach } from "vitest";
import { UpstashRateLimitStore } from "./rateLimit";

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe("UpstashRateLimitStore when Redis is down", () => {
  it.each([
    ["HTTP 500", async () => new Response("err", { status: 500 })],
    ["network error", async () => { throw new TypeError("fetch failed"); }],
  ])("%s → limits still apply (per instance), and it says so once", async (_l, impl) => {
    vi.stubGlobal("fetch", vi.fn(impl));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const store = new UpstashRateLimitStore("https://redis.example", "t");
    const results = [];
    for (let i = 0; i < 4; i++) results.push((await store.hit("reset-global:2026-10-01", 3, 60_000)).ok);
    expect(results).toEqual([true, true, true, false]);       // the 4th is refused, not waved through
    expect(log).toHaveBeenCalledTimes(1);                       // sampled
  });
});
