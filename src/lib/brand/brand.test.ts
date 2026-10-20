import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  PLATFORM_BRAND, brandFromOrg, brandTitle, contactLine, hostOf, isPlatformHost, normalizeDomain, senderFor, slugFromHost, subdomainOrigin,
} from "./brand";
import { sanitizeBranding } from "./sanitize";
import { orgWelcomeEmail, passwordResetEmail, studentInviteEmail, accountAccessEmail, planNotificationEmail, lapsedNudgeEmail } from "@/lib/email/templates";
import { certificateFooter } from "@/lib/certificate/renderCertificate";
import { certificateHost } from "@/lib/certificate/issuer";
import { quotaMessage, quotaOf } from "@/lib/team/quota";

const PNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
const WL_ORG = {
  id: "11111111-2222-3333-4444-555555555555",
  name: "Cyber College",
  custom_domain: "soc.college.example",
  branding: { white_label: true, product_name: "College SOC", logo_data: PNG, support_email: "help@college.example", color: "#ff8800" },
};

describe("hosts and domains", () => {
  it("strips port, case and trailing dot from the Host header", () => {
    expect(hostOf("SOC.College.Example:443")).toBe("soc.college.example");
    expect(hostOf("soc.college.example.")).toBe("soc.college.example");
    expect(hostOf(null)).toBe("");
  });
  it("never looks up a brand for the platform's own hosts", () => {
    for (const h of ["", "localhost", "127.0.0.1", "hackthesoc.app", "www.hackthesoc.app", "hack-the-soc.vercel.app"]) {
      expect(isPlatformHost(h)).toBe(true);
    }
    expect(isPlatformHost("soc.college.example")).toBe(false);
    expect(isPlatformHost("wl-demo.localhost")).toBe(false); // local stand-in for a customer domain
  });
  it("normalises an admin-typed domain and refuses junk or platform hosts", () => {
    expect(normalizeDomain(" https://SOC.College.Example/login ")).toBe("soc.college.example");
    expect(normalizeDomain("not a domain")).toBeNull();
    expect(normalizeDomain("www.hackthesoc.app")).toBeNull();
    expect(normalizeDomain("x.vercel.app")).toBeNull();
  });
});

describe("wildcard base domain (<slug>.<NEXT_PUBLIC_WL_BASE_DOMAIN>)", () => {
  const prev = process.env.NEXT_PUBLIC_WL_BASE_DOMAIN;
  beforeEach(() => { process.env.NEXT_PUBLIC_WL_BASE_DOMAIN = "soc-academy.example"; });
  afterEach(() => { if (prev === undefined) delete process.env.NEXT_PUBLIC_WL_BASE_DOMAIN; else process.env.NEXT_PUBLIC_WL_BASE_DOMAIN = prev; });

  it("maps a one-label subdomain to the org slug, nothing else", () => {
    expect(slugFromHost("northwind.soc-academy.example")).toBe("northwind");
    expect(slugFromHost("a.b.soc-academy.example")).toBeNull();
    expect(slugFromHost("www.soc-academy.example")).toBeNull();
    expect(slugFromHost("soc-academy.example")).toBeNull();
    expect(slugFromHost("northwind.other.example")).toBeNull();
    expect(isPlatformHost("soc-academy.example")).toBe(true);
    expect(isPlatformHost("northwind.soc-academy.example")).toBe(false);
  });
  it("gives a white-label org without its own domain an automatic address", () => {
    const b = brandFromOrg({ ...WL_ORG, slug: "northwind", custom_domain: null });
    expect(b.origin).toBe("https://northwind.soc-academy.example");
    expect(brandFromOrg({ ...WL_ORG, slug: "northwind" }).origin).toBe("https://soc.college.example"); // own domain wins
    expect(subdomainOrigin("northwind")).toBe("https://northwind.soc-academy.example");
  });
  it("won't take a base-domain host as an org's own domain", () => {
    expect(normalizeDomain("x.soc-academy.example")).toBeNull();
  });
  it("has no automatic address when the base domain isn't set", () => {
    delete process.env.NEXT_PUBLIC_WL_BASE_DOMAIN;
    expect(slugFromHost("northwind.soc-academy.example")).toBeNull();
    expect(subdomainOrigin("northwind")).toBeNull();
  });
});

describe("brandFromOrg", () => {
  it("is the platform brand unless the org is white label", () => {
    expect(brandFromOrg(null)).toBe(PLATFORM_BRAND);
    expect(brandFromOrg({ ...WL_ORG, branding: { ...WL_ORG.branding, white_label: false } })).toBe(PLATFORM_BRAND);
  });
  it("carries the org's name, logo route, domain and support contact", () => {
    const b = brandFromOrg(WL_ORG);
    expect(b.whiteLabel).toBe(true);
    expect(b.productName).toBe("College SOC");
    expect(b.logoSrc).toBe(`/api/brand/logo?org=${WL_ORG.id}`);
    expect(b.origin).toBe("https://soc.college.example");
    expect(b.supportEmail).toBe("help@college.example");
    expect(b.color).toBe("#ff8800");
  });
  it("falls back to the org name and drops an SVG or malformed logo", () => {
    const b = brandFromOrg({ ...WL_ORG, branding: { white_label: true, logo_data: "data:image/svg+xml;base64,PHN2Zz4=" } });
    expect(b.productName).toBe("Cyber College");
    expect(b.logoSrc).toBeNull();
  });
  it("names the brand in titles, contact lines and senders", () => {
    const b = brandFromOrg(WL_ORG);
    expect(brandTitle("Learning Rooms", b)).toBe("Learning Rooms // College SOC");
    expect(brandTitle("Learning Rooms", PLATFORM_BRAND)).toBe("Learning Rooms // HACK THE SOC");
    expect(contactLine(b)).toBe("Contact help@college.example");
    expect(contactLine(PLATFORM_BRAND)).toBe("Contact HACK THE SOC");
    expect(senderFor(PLATFORM_BRAND)).toBe("");
    expect(senderFor(b)).toBe("College SOC <noreply@hackthesoc.app>");
    expect(senderFor(brandFromOrg({ ...WL_ORG, branding: { ...WL_ORG.branding, email_from: "College SOC <noreply@college.example>" } })))
      .toBe("College SOC <noreply@college.example>");
  });
});

describe("sanitizeBranding", () => {
  it("keeps only whitelisted, valid fields", () => {
    const r = sanitizeBranding({ white_label: true, product_name: " <b>College</b> SOC ", support_email: "a@b.example", junk: "x", logo_data: PNG });
    expect("error" in r).toBe(false);
    if ("error" in r) return;
    expect(r.branding).toEqual({ white_label: true, product_name: "bCollege/b SOC", support_email: "a@b.example", logo_data: PNG });
    expect(r.keepLogo).toBe(false);
  });
  it("keeps the stored logo when none is sent, removes it on an empty string", () => {
    const keep = sanitizeBranding({ white_label: true });
    const remove = sanitizeBranding({ white_label: true, logo_data: "" });
    expect("error" in keep || keep.keepLogo).toBe(true);
    expect("error" in remove ? true : remove.keepLogo).toBe(false);
  });
  it("refuses an SVG logo, a bad address and a header-injecting sender", () => {
    expect(sanitizeBranding({ logo_data: "data:image/svg+xml;base64,PHN2Zz4=" })).toHaveProperty("error");
    expect(sanitizeBranding({ support_email: "nope" })).toHaveProperty("error");
    expect(sanitizeBranding({ email_from: "X <a@b.example>\r\nBcc: c@d.example" })).toHaveProperty("error");
  });
});

describe("white-label artefacts never show the platform", () => {
  const wl = { productName: "College SOC", whiteLabel: true, logoUrl: "https://soc.college.example/api/brand/logo?org=x" };
  const mails = [
    orgWelcomeEmail({ orgName: "Cyber College", adminLink: "https://soc.college.example/join?token=t", brand: wl }),
    passwordResetEmail({ resetLink: "https://soc.college.example/update-password?token_hash=h", brand: wl }),
    studentInviteEmail({ orgName: "Cyber College", joinLink: "https://soc.college.example/join?token=t", brand: wl }),
    accountAccessEmail({ orgName: "Cyber College", link: "https://soc.college.example/x", brand: wl }),
    planNotificationEmail({ kind: "plan_assigned", planTitle: "Week 1", orgName: "Cyber College", link: "https://soc.college.example/learn", brand: wl }),
    lapsedNudgeEmail({ name: "Dana", daysAway: 9, resumeLink: "https://soc.college.example/rooms", brand: wl }),
  ];
  it("emails carry the org's name and logo, not HACK THE SOC", () => {
    for (const m of mails) {
      expect(`${m.subject}\n${m.html}\n${m.text}`).not.toMatch(/hack\s*(<[^>]+>)?\s*the\s*(<[^>]+>)?\s*soc|hackthesoc/i);
    }
    expect(mails[1].subject).toBe("Reset your College SOC password");
    expect(mails[1].html).toContain('src="https://soc.college.example/api/brand/logo?org=x"');
  });
  it("platform emails are unchanged", () => {
    expect(passwordResetEmail({ resetLink: "https://www.hackthesoc.app/x" }).subject).toBe("Reset your HACK THE SOC password");
  });
  it("certificates print the org's domain, or none, never the platform's", () => {
    const b = brandFromOrg(WL_ORG);
    expect(certificateHost(b)).toBe("soc.college.example");
    expect(certificateHost({ ...b, origin: null })).toBe("");
    expect(certificateHost(PLATFORM_BRAND)).toBe("www.hackthesoc.app");
    expect(certificateFooter(WL_ORG.id, "Cyber College", "")).toBe("Issued by Cyber College · SOC Analyst Training");
  });
  it("quota messages send admins to the org's own support", () => {
    expect(quotaMessage(quotaOf(0, 0), contactLine(brandFromOrg(WL_ORG)))).toContain("Contact help@college.example");
    expect(quotaMessage(quotaOf(0, 0))).toContain("Contact HACK THE SOC");
  });
});

describe("route titles", () => {
  // Every layout title goes through brandMetadata, so a white-label domain never shows
  // "// HACK THE SOC" in the tab (the root layout's platform branch is the only literal).
  function layouts(dir: string): string[] {
    return readdirSync(dir).flatMap(n => {
      const p = join(dir, n);
      return statSync(p).isDirectory() ? layouts(p) : n === "layout.tsx" ? [p] : [];
    });
  }
  it("no route layout hard-codes the platform name", () => {
    const root = join(process.cwd(), "src", "app");
    const offenders = layouts(root).filter(p => p !== join(root, "layout.tsx") && /HACK THE SOC/.test(readFileSync(p, "utf8")));
    expect(offenders).toEqual([]);
  });
});
