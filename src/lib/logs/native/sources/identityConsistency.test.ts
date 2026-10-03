// Cross-row consistency of the identity / collaboration / ITSM / firewall renderers, checked on
// the sessions trainees actually get (instantiateStory + applyStack, every company, the company's
// own products and chosen IdP / collab / firewall stacks):
//   • one client IP → one place, one network owner, one anonymizer flag in every Okta record;
//   • one user → one Entra object id across Entra, the UAL and Defender for Office 365;
//   • one Okta login flow → one externalSessionId (MFA and session.start share it);
//   • a UAL record's AADSessionId is its sign-in's sessionId, its token never issued before it;
// plus focused unit checks of the single-record fixes (CA status, PRT, security-info method,
// Malware never Delivered, first contact, inbound URL rows).
import { describe, it, expect } from "vitest";
import { storiesForCompany, instantiateStory, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { normalizeHostIps } from "@/lib/sim/hostIdentity";
import type { TelemetryEvent } from "@/lib/sim/types";
import { applyStack, authoredOf, nativeView, storyFitsStack, storyHonoursLocks } from "../index";
import { PRODUCT_LABEL, type Stack } from "../stack";
import { makeCtx } from "../ctx";
import { threadIdentityContext } from "./_identity-common";
import { source as entra } from "./entra";
import { source as okta } from "./okta";
import { source as mdo } from "./defender_o365";
import { source as paloalto } from "./paloalto";
import { source as fortigate } from "./fortigate";

const COMPANIES: [string, TelemetryEvent[]][] = ([
  ["nexacorp", BENIGN_EVENTS], ["medcore", COMPANY_EVENTS.medcore], ["rocketstack", COMPANY_EVENTS.rocketstack],
  ["globallogis", COMPANY_EVENTS.globallogis], ["quantumbank", COMPANY_EVENTS.quantumbank],
] as [string, TelemetryEvent[]][]).map(([c, pool]) => [c, normalizeHostIps(pool)]);
const STACKS: Stack[] = [{}, { idp: "okta" }, { idp: "entra", collab: "m365" }];
const edrFor = (company: string, stack: Stack) => (stack.edr && PRODUCT_LABEL[stack.edr]) || COMPANY_PROFILES.find(c => c.id === company)?.architecture.edr;

interface Run { company: string; stack: Stack; story: AttackStory; events: TelemetryEvent[] }
let cache: Run[] | null = null;
function runs(): Run[] {
  if (cache) return cache;
  cache = [];
  for (const [company, pool] of COMPANIES) for (const stack of STACKS) {
    const seen = new Set<string>();
    for (const diff of ["easy", "medium", "hard"] as const) for (const s of storiesForCompany(company, diff)) {
      if (seen.has(s.id)) continue; seen.add(s.id);
      const evs = (instantiateStory(s, pool, edrFor(company, stack), company).events ?? []).map(e => applyStack(e, company, stack));
      if (!(Object.keys(stack).length ? storyFitsStack(evs, company, stack) : storyHonoursLocks(evs, company))) continue;
      cache.push({ company, stack, story: s, events: evs });
    }
  }
  return cache;
}
const tag = (r: Run, e: TelemetryEvent) => `${r.company}${Object.keys(r.stack).length ? JSON.stringify(r.stack) : ""} ${r.story.id} ${authoredOf(e).id}`;
type Rec = Record<string, any>;

describe("identity consistency across a story (runtime sessions)", { timeout: 300_000 }, () => {
  it("Okta: one client IP is one place, one network owner and one anonymizer flag — in every story", () => {
    const byIp = new Map<string, Map<string, string>>();
    let n = 0;
    for (const r of runs()) for (const e of r.events) {
      const v = nativeView(e, r.company, r.stack);
      if (v?.log.sourceId !== "okta") continue;
      const rec = v.log.record as Rec;
      const ip = rec.client?.ipAddress;
      if (!ip) continue;
      n++;
      const g = rec.client.geographicalContext;
      const key = `${g.city}/${g.country}/${rec.securityContext.isp}/AS${rec.securityContext.asNumber}/proxy=${rec.securityContext.isProxy}`;
      (byIp.get(ip) ?? byIp.set(ip, new Map()).get(ip)!).set(key, tag(r, e));
    }
    expect(n).toBeGreaterThan(50);
    const split = [...byIp].filter(([, m]) => m.size > 1).map(([ip, m]) => `${ip}: ${[...m].map(([k, w]) => `${k} (${w})`).join(" | ")}`);
    expect(split).toEqual([]);
  });

  it("Okta: a Tor exit is an anonymizer with its operator's ASN, never the head office's ISP", () => {
    let tor = 0;
    for (const r of runs()) for (const e of r.events) {
      const v = nativeView(e, r.company, r.stack);
      if (v?.log.sourceId !== "okta" || !/^185\.220\.10[0-3]\./.test((v.log.record as Rec).client?.ipAddress ?? "")) continue;
      tor++;
      expect((v.log.record as Rec).securityContext.isProxy, tag(r, e)).toBe(true);
      expect((v.log.record as Rec).securityContext.isp, tag(r, e)).toBe("tor exit node");
    }
    expect(tor).toBeGreaterThan(0);
  });

  it("Okta: the session-bearing rows of one login flow share one externalSessionId", () => {
    // One login flow = one user's sign-in / push / MFA rows from one address, each within 10 minutes of the last.
    const problems: string[] = [];
    let flowsSeen = 0;
    for (const r of runs()) {
      const rows: { key: string; t: number; sid: string }[] = [];
      for (const e of r.events) {
        const v = nativeView(e, r.company, r.stack);
        if (v?.log.sourceId !== "okta") continue;
        const rec = v.log.record as Rec;
        const sid = rec.authenticationContext.externalSessionId;
        if (!sid || sid === "unknown" || !["user.session.start", "user.authentication.auth_via_mfa", "system.push.send_factor_verify_push", "policy.evaluate_sign_on"].includes(rec.eventType)) continue;
        rows.push({ key: `${rec.actor.alternateId}|${rec.client.ipAddress}`, t: v.log.timeMs, sid });
      }
      rows.sort((a, b) => a.t - b.t);
      const last = new Map<string, { t: number; sids: Set<string> }>();
      const flows: { key: string; sids: Set<string> }[] = [];
      for (const row of rows) {
        const cur = last.get(row.key);
        if (cur && row.t - cur.t <= 600_000) { cur.t = row.t; cur.sids.add(row.sid); continue; }
        const f = { t: row.t, sids: new Set([row.sid]) };
        last.set(row.key, f); flows.push({ key: row.key, sids: f.sids });
      }
      for (const f of flows) { if (f.sids.size) flowsSeen++; if (f.sids.size > 1) problems.push(`${r.company} ${r.story.id} ${f.key}: ${[...f.sids].join(", ")}`); }
    }
    expect(flowsSeen).toBeGreaterThan(10);
    expect(problems).toEqual([]);
  });

  it("Entra / UAL / MDO: one user has one object id in every Microsoft record of a story", () => {
    const problems: string[] = [];
    let checked = 0;
    for (const r of runs()) {
      const ids = new Map<string, Set<string>>();
      const add = (upn: unknown, id: unknown) => { if (typeof upn !== "string" || !upn.includes("@") || typeof id !== "string" || !id) return; (ids.get(upn.toLowerCase()) ?? ids.set(upn.toLowerCase(), new Set()).get(upn.toLowerCase())!).add(id); };
      for (const e of r.events) {
        const v = nativeView(e, r.company, r.stack);
        if (!v) continue;
        const rec = v.log.record as Rec;
        if (v.log.sourceId === "entra") {
          if (v.log.kind === "signIn") add(rec.userPrincipalName, rec.userId);
          else { add(rec.initiatedBy?.user?.userPrincipalName, rec.initiatedBy?.user?.id); for (const t of rec.targetResources ?? []) if (t.type === "User") add(t.userPrincipalName, t.id); }
        } else if (v.log.sourceId === "m365") add(rec.UserId, rec.TokenObjectId);
        else if (v.log.sourceId === "defender_o365") add(rec.properties?.RecipientEmailAddress, rec.properties?.RecipientObjectId);
      }
      for (const [u, s] of ids) { checked++; if (s.size > 1) problems.push(`${r.company} ${r.story.id} ${u}: ${[...s].join(", ")}`); }
    }
    expect(checked).toBeGreaterThan(20);
    expect(problems).toEqual([]);
  });

  it("UAL: AppAccessContext names the sign-in's Entra session and a token issued no earlier than that sign-in", () => {
    const problems: string[] = [];
    for (const r of runs()) {
      const signIns: { upn: string; ip: string; sid: string; t: number }[] = [];
      for (const e of [...r.events].sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts))) {
        const v = nativeView(e, r.company, r.stack);
        if (!v) continue;
        const rec = v.log.record as Rec;
        if (v.log.sourceId === "entra" && v.log.kind === "signIn" && rec.sessionId) signIns.push({ upn: rec.userPrincipalName, ip: rec.ipAddress, sid: rec.sessionId, t: v.log.timeMs });
        if (v.log.sourceId !== "m365" || !rec.AppAccessContext) continue;
        const ip = rec.ClientIPAddress ?? String(rec.ClientIP ?? "").replace(/:\d+$/, "");
        const si = signIns.filter(s => s.upn === rec.UserId && s.ip === ip && s.t <= v.log.timeMs && v.log.timeMs - s.t < 3_600_000).pop();
        if (!si) continue;
        if (rec.AppAccessContext.AADSessionId !== si.sid) problems.push(`${tag(r, e)}: AADSessionId ${rec.AppAccessContext.AADSessionId} ≠ sign-in ${si.sid}`);
        if (Date.parse(`${rec.AppAccessContext.IssuedAtTime}Z`) < si.t - 1000) problems.push(`${tag(r, e)}: token issued ${rec.AppAccessContext.IssuedAtTime} before the sign-in`);
      }
    }
    expect(problems).toEqual([]);
  });
});

// ── single-record fixes ─────────────────────────────────────────────────────────
const ctx = makeCtx("nexacorp");
const ev = (o: Partial<TelemetryEvent>): TelemetryEvent => ({ id: "t1", ts: "2026-05-08T08:12:00.000Z", source: "o365", event_type: "auth_success", ...o } as TelemetryEvent);

describe("Entra sign-in / audit coherence", () => {
  it("conditionalAccessStatus notApplied → no applied policy claims success (the MFA came from per-user MFA)", () => {
    const log = entra.fromTelemetry(ev({ vendor: "Microsoft Entra ID", src_ip: "91.108.56.122", user_email: "dba@nexacorp.com", raw: {
      "azure.signinlogs.resultType": "0", "azure.signinlogs.conditional_access_status": "notApplied", "azure.signinlogs.authentication_requirement": "multiFactorAuthentication",
      "authentication.mfa": "Microsoft Authenticator Push" } }), ctx)!;
    const r = log.record as Rec;
    expect(r.conditionalAccessStatus).toBe("notApplied");
    expect(r.appliedConditionalAccessPolicies.every((p: Rec) => p.result === "notApplied")).toBe(true);
    expect(r.authenticationRequirementPolicies).toEqual([{ requirementProvider: "user", detail: "Per-user MFA" }]);
  });
  it("a Primary Refresh Token is never presented by an unmanaged browser session", () => {
    const log = entra.fromTelemetry(ev({ vendor: "Microsoft Entra ID", src_ip: "91.243.24.19", user_email: "dba@nexacorp.com", raw: {
      "azure.signinlogs.resultType": "0", "azure.signinlogs.properties.incomingTokenType": "primaryRefreshToken",
      "azure.signinlogs.properties.deviceDetail.isManaged": "false", "azure.signinlogs.properties.clientAppUsed": "Browser" } }), ctx)!;
    expect((log.record as Rec).incomingTokenType).toBe("none");
  });
  it("an office-LAN sign-in shows the company egress, inside the Corporate HQ trusted location", () => {
    const log = entra.fromTelemetry(ev({ vendor: "Microsoft Entra ID", src_ip: "10.10.20.14", user_email: "a.cohen@nexacorp.com", hostname: "WS-1", raw: { "azure.signinlogs.resultType": "0" } }), ctx)!;
    const r = log.record as Rec;
    expect(r.ipAddress).not.toMatch(/^10\./);
    expect(r.networkLocationDetails[0]?.networkType).toBe("trustedNamedLocation");
  });
  it("User registered security info carries the registered method and the modified properties", () => {
    const log = entra.fromTelemetry(ev({ vendor: "Microsoft Entra ID", event_type: "account_modify", src_ip: "91.132.139.204", user_email: "p.wright@nexacorp.com", raw: {
      "azure.auditlogs.properties.activityDisplayName": "User registered security info",
      "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].displayName": "StrongAuthenticationMethod",
      "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].oldValue": "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true}]",
      "azure.auditlogs.properties.targetResources[0].modifiedProperties[0].newValue": "[{\"MethodType\":\"PhoneAppNotification\",\"Default\":true},{\"MethodType\":\"OneWaySms\",\"Default\":false}]" } }), ctx)!;
    const r = log.record as Rec;
    expect(r.resultReason).toBe("User registered Mobile Phone SMS");
    expect(r.targetResources[0].modifiedProperties[0].displayName).toBe("StrongAuthenticationMethod");
    const asOkta = okta.fromTelemetry(ev({ vendor: "Microsoft Entra ID", event_type: "account_modify", src_ip: "91.132.139.204", user_email: "p.wright@nexacorp.com", raw: {
      "azure.auditlogs.properties.activityDisplayName": "User registered security info", "azure.auditlogs.properties.resultReason": "User registered Software OATH token" } }), ctx)!;
    expect((asOkta.record as Rec).target[1].displayName).toBe("Google Authenticator");
  });
});

describe("Okta risk context", () => {
  it("a first-seen foreign anonymizer login is not all-NEGATIVE / LOW", () => {
    const log = okta.fromTelemetry(ev({ source: "okta", vendor: "Okta", src_ip: "185.220.101.15", user_email: "m.levi@nexacorp.com", mitre_technique: "T1078", raw: {
      "okta.eventType": "user.session.start", "okta.outcome.result": "SUCCESS" } }), ctx)!;
    const d = (log.record as Rec).debugContext.debugData;
    expect(d.behaviors).toContain("New IP=POSITIVE");
    expect(d.risk).toContain("level=HIGH");
    expect((log.record as Rec).securityContext.isProxy).toBe(true);
  });
  it("the user's own baseline sign-in stays NEGATIVE / LOW", () => {
    const log = okta.fromTelemetry(ev({ source: "okta", vendor: "Okta", src_ip: "86.150.23.44", user_email: "m.levi@nexacorp.com", is_baseline: true, geo: { country: "France", city: "Paris" }, raw: {
      "okta.eventType": "user.session.start", "okta.outcome.result": "SUCCESS" } }), ctx)!;
    const d = (log.record as Rec).debugContext.debugData;
    expect(d.behaviors).not.toContain("POSITIVE");
    expect(d.risk).toBe("{level=LOW}");
  });
});

describe("story threading", () => {
  it("carries the authored geo of an IP to its other rows and unifies the flow's Okta session", () => {
    const base = { source: "okta" as const, vendor: "Okta", src_ip: "138.199.59.21", user_email: "t.levy@rocketstack.io" };
    const [a, b] = threadIdentityContext([
      ev({ ...base, id: "s1", ts: "2026-09-25T06:52:08Z", geo: { country: "Poland", city: "Warsaw" }, raw: { "okta.eventType": "user.session.start", "okta.outcome.result": "SUCCESS", "okta.securityContext.isProxy": "true", "okta.authenticationContext.externalSessionId": "102AAA" } }),
      ev({ ...base, id: "s2", ts: "2026-09-25T06:52:31Z", event_type: "mfa_challenge", raw: { "okta.eventType": "user.authentication.auth_via_mfa", "okta.outcome.result": "SUCCESS", "okta.securityContext.isProxy": "false", "okta.authenticationContext.externalSessionId": "102BBB" } }),
    ]);
    expect(b.geo).toMatchObject({ country: "Poland", city: "Warsaw", anonymous: true });
    expect(b.raw?.["okta.authenticationContext.externalSessionId"]).toBe("102AAA");
    expect(a.raw?.["okta.authenticationContext.externalSessionId"]).toBe("102AAA");
  });
  it("a sender who already mailed the recipient is not a first contact", () => {
    const mail = (id: string, ts: string) => ev({ id, ts, event_type: "email_received", vendor: "Microsoft Defender for Office 365", user_email: "d.morgan@nexacorp.com",
      raw: { "email.from.address": "d.holloway@brightwaterfreight.co.uk", "email.to.address": "d.morgan@nexacorp.com", "email.subject": "Invoice" }, expected_verdict: id === "m2" ? "tp" : undefined });
    const out = threadIdentityContext([mail("m1", "2026-09-23T14:06:12Z"), mail("m2", "2026-09-24T08:13:22Z")]);
    const second = mdo.fromTelemetry(out[1], ctx)!;
    expect((second.record as Rec).properties.IsFirstContact).toBe(0);
  });
});

describe("Defender for Office 365 delivery coherence", () => {
  it("a delivered message never carries a Malware verdict (clean at delivery — ZAP convicts later)", () => {
    const log = mdo.fromTelemetry(ev({ id: "m", event_type: "email_received", vendor: "Microsoft Defender for Office 365", user_email: "s.patel@nexacorp.com", src_ip: "45.148.10.203", raw: {
      "email.from.address": "billing@client-invoices-portal.info", "email.to.address": "s.patel@nexacorp.com", "email.attachment.name": "Q3.docm",
      "action_result": "delivered", "block.reason": "No matching transport rule — macro-enabled document type not blocklisted", "threat.category": "Phishing" } }), ctx)!;
    const p = (log.record as Rec).properties;
    expect(p.DeliveryAction).toBe("Delivered");
    expect(p.ThreatTypes).not.toContain("Malware");
    expect(p.SenderIPv4).toBe("45.148.10.203");
  });
  it("every inbound message names its connecting server", () => {
    const log = mdo.fromTelemetry(ev({ id: "m3", event_type: "email_received", vendor: "Microsoft Defender for Office 365", user_email: "t.brooks@nexacorp.com",
      raw: { "email.from.address": "it-support@nexacorp-secure-portal.com", "email.to.address": "t.brooks@nexacorp.com" } }), ctx)!;
    expect((log.record as Rec).properties.SenderIPv4).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
  });
});

describe("firewall URL rows", () => {
  const waf = ev({ id: "w1", source: "firewall", vendor: "FortiGate", event_type: "http_request", src_ip: "185.220.101.47", dst_ip: "156.146.62.14", dst_port: 443,
    network: { url: "https://vpn.nexacorp.com/api/v2/cmdb/system/admin/", domain: "vpn.nexacorp.com", method: "GET" },
    raw: { "data.type": "utm", "data.subtype": "waf", "data.url": "/api/v2/cmdb/system/admin/", "data.method": "GET", "data.action": "pass" } });
  it("an authored inbound web-filter / WAF row renders as the product's URL log, with the URL", () => {
    const pan = paloalto.fromTelemetry(waf, ctx)!;
    expect(pan.record.type).toBe("THREAT");
    expect(pan.record.subtype).toBe("url");
    expect(String(pan.record.misc)).toContain("/api/v2/cmdb/system/admin/");
    const fgt = fortigate.fromTelemetry(waf, ctx)!;
    expect(fgt.kind).toBe("utm/webfilter");
    expect(fgt.record.direction).toBe("incoming");
    expect(String(fgt.record.url)).toContain("/api/v2/cmdb/system/admin/");
  });
});
