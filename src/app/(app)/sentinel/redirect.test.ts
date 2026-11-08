// /sentinel is the console's old address: it redirects to /xdr with the same query, so old links,
// bookmarks and windows opened before the rename keep working (owner, 2026-11-08).
import { describe, it, expect, vi } from "vitest";

const redirect = vi.fn((url: string) => { throw Object.assign(new Error("NEXT_REDIRECT"), { url }); });
vi.mock("next/navigation", () => ({ redirect: (u: string) => redirect(u) }));

import SentinelRedirect from "./page";
import { xdrHref } from "@/lib/team/twoWindows";

const TEAM = "bb4dbbdc-8253-48fe-8202-9b72d26b4a6b";

describe("/sentinel", () => {
  it("redirects to /xdr with the query string", async () => {
    await expect(SentinelRedirect({ searchParams: Promise.resolve({ team: TEAM, u: "d575ffca-ff4e-4400-95c0-9ed04523c5d0", r: "t2", incident: "inc-7" }) })).rejects.toThrow("NEXT_REDIRECT");
    expect(redirect).toHaveBeenCalledWith(`/xdr?team=${TEAM}&u=d575ffca-ff4e-4400-95c0-9ed04523c5d0&r=t2&incident=inc-7`);
  });

  it("with no query goes to /xdr itself", async () => {
    await expect(SentinelRedirect({ searchParams: Promise.resolve({}) })).rejects.toThrow("NEXT_REDIRECT");
    expect(redirect).toHaveBeenLastCalledWith("/xdr");
  });
});

describe("xdrHref", () => {
  it("keeps every key, repeated keys and encoding", () => {
    expect(xdrHref({ team: TEAM, host: ["WS 1", "WS-2"], skip: undefined })).toBe(`/xdr?team=${TEAM}&host=WS+1&host=WS-2`);
    expect(xdrHref(new URLSearchParams("team=a&host=b%26c"))).toBe("/xdr?team=a&host=b%26c");
    expect(xdrHref(null)).toBe("/xdr");
  });
});
