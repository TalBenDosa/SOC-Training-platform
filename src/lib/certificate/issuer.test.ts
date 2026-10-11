import { describe, it, expect } from "vitest";
import { certificateIssuer, hasOrgIssuer, PLATFORM_ISSUER, PRODUCTION_ORIGIN, PRODUCTION_HOST } from "./issuer";
import { ROOT_ORG_ID } from "@/lib/org/rootEnvironment";

describe("certificateIssuer", () => {
  it("uses a real organisation's name", () => {
    expect(certificateIssuer("org-college-1", "Tel Aviv Cyber College")).toBe("Tel Aviv Cyber College");
    expect(hasOrgIssuer("org-college-1", "Tel Aviv Cyber College")).toBe(true);
  });

  it("never prints the placeholder 'Individual' (or other no-org names)", () => {
    for (const n of ["Individual", "individual", "Individuals", "Internal / Default", "Default", "Personal", " "]) {
      expect(certificateIssuer("org-x", n)).toBe(PLATFORM_ISSUER);
    }
  });

  it("falls back to the platform for the root/system org whatever it is called", () => {
    expect(certificateIssuer(ROOT_ORG_ID, "Acme Security")).toBe(PLATFORM_ISSUER);
    expect(hasOrgIssuer(ROOT_ORG_ID, "Acme Security")).toBe(false);
  });

  it("falls back to the platform when there is no org at all", () => {
    expect(certificateIssuer(null, null)).toBe(PLATFORM_ISSUER);
    expect(certificateIssuer(undefined, undefined)).toBe(PLATFORM_ISSUER);
  });
});

describe("production domain", () => {
  it("is the canonical www.hackthesoc.app, not the vercel alias", () => {
    expect(PRODUCTION_ORIGIN).toBe("https://www.hackthesoc.app");
    expect(PRODUCTION_HOST).toBe("www.hackthesoc.app");
    expect(PRODUCTION_ORIGIN).not.toMatch(/vercel\.app|localhost/);
  });
});
