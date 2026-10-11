/** SEC-03 / SEC-09 / SEC-15: the page CSP and the cross-site write check. */
import { describe, it, expect } from "vitest";
import { NextRequest } from "next/server";
import { buildPageCsp, makeNonce, supabaseHost } from "./csp";
import { isCrossSiteWrite } from "./csrf";

describe("page CSP", () => {
  const csp = buildPageCsp({ nonce: "abc123==", dev: false, supabaseUrl: "https://wrxhxtdllbctsawvewue.supabase.co" });
  const directive = (name: string) => csp.split("; ").find(d => d.startsWith(`${name} `)) ?? "";

  it("scripts run only with this response's nonce — no unsafe-inline / unsafe-eval in production", () => {
    expect(directive("script-src")).toBe("script-src 'self' 'nonce-abc123==' 'strict-dynamic'");
    expect(csp).not.toMatch(/script-src[^;]*unsafe/);
  });
  it("development keeps unsafe-eval (React dev tooling), still no unsafe-inline", () => {
    const dev = buildPageCsp({ nonce: "n", dev: true, supabaseUrl: undefined });
    expect(dev).toMatch(/script-src 'self' 'nonce-n' 'strict-dynamic' 'unsafe-eval'/);
    expect(dev).not.toMatch(/script-src[^;]*unsafe-inline/);
  });
  it("Supabase is pinned to this project's host, not *.supabase.co", () => {
    expect(directive("connect-src")).toBe("connect-src 'self' https://wrxhxtdllbctsawvewue.supabase.co wss://wrxhxtdllbctsawvewue.supabase.co");
    expect(csp).not.toContain("*.supabase.co");
    expect(supabaseHost("not a url")).toBeNull();
  });
  it("keeps the structural protections", () => {
    for (const d of ["frame-ancestors 'none'", "object-src 'none'", "base-uri 'self'", "form-action 'self'"]) expect(csp).toContain(d);
  });
  it("nonces are fresh and unguessable-length", () => {
    const a = makeNonce(), b = makeNonce();
    expect(a).not.toBe(b);
    expect(atob(a).length).toBe(16);
  });
});

describe("cross-site write check", () => {
  const req = (method: string, headers: Record<string, string>, path = "/api/account") =>
    new NextRequest(`https://www.hackthesoc.app${path}`, { method, headers });
  it.each([
    ["POST", { "sec-fetch-site": "cross-site" }, true],
    ["POST", { "sec-fetch-site": "same-site" }, true],           // a sibling subdomain is not this app
    ["DELETE", { origin: "https://evil.example" }, true],
    ["POST", { "sec-fetch-site": "same-origin" }, false],
    ["POST", { "sec-fetch-site": "none" }, false],                // typed into the address bar / bookmark
    ["POST", { origin: "https://www.hackthesoc.app" }, false],
    ["POST", {}, false],                                          // server-to-server: judged by its own credentials
    ["GET", { "sec-fetch-site": "cross-site" }, false],           // safe methods are not writes
  ] as const)("%s %j → refused=%s", (method, headers, refused) => {
    expect(isCrossSiteWrite(req(method, headers))).toBe(refused);
  });
  it("Vercel cron is exempt", () => {
    expect(isCrossSiteWrite(req("POST", { "sec-fetch-site": "cross-site" }, "/api/cron/expire-orgs"))).toBe(false);
  });
});
