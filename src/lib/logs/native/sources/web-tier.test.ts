// The four web-tier modules (aws_waf, azure_waf, iis, nginx): card samples validate, every story row
// converts cleanly and deterministically, evidence survives, the wire lines parse back, and each use
// case fires on attack logs while staying quiet on noise.
import { describe, expect, it } from "vitest";
import { source as awsWaf, kindOf as awsKind } from "./aws_waf";
import { source as azureWaf, kindOf as azureKind } from "./azure_waf";
import { FIELDS, source as iis, kindOf as iisKind, rawLineOf as iisLine } from "./iis";
import { source as nginx, kindOf as nginxKind, timeLocal } from "./nginx";
import { WEB_WAF_VENDOR } from "./_web-common";
import { standardChecks } from "../testing/standardChecks";
import { corpusFor } from "../testing/corpus";
import { makeCtx } from "../ctx";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import type { NativeSource } from "../types";

const neutral = (s: NativeSource) => corpusFor(s.schema.telemetrySources).filter(c => c.storyId?.startsWith("web-"));

/** Volume rules: a story shows a sample of the wave, so they are proven on a full wave below. */
const VOLUME = new Set(["iis.login_failures", "nginx.login_failures"]);

const SUITES: [string, NativeSource, (r: Record<string, unknown>) => string | null, string, number][] = [
  ["aws_waf", awsWaf, awsKind, "waf-aws.md", 4],
  ["azure_waf", azureWaf, azureKind, "waf-azure.md", 4],
  ["iis", iis, iisKind, "web-iis.md", 2],
  ["nginx", nginx, nginxKind, "web-nginx.md", 3],
];

for (const [name, source, kindOf, card, samples] of SUITES) {
  describe(name, () => {
    const rep = standardChecks(source, kindOf, { cards: [card], evidence: c => (c.storyId?.startsWith("web-") ? [c.ev.src_ip].filter((x): x is string => !!x) : []) });
    it("card samples validate", () => {
      expect(rep.cardChecked).toBeGreaterThanOrEqual(samples);
      expect(rep.cardViolations).toEqual([]);
    });
    it("every event converts with zero violations, deterministically, keeping the client address", () => {
      expect(neutral(source).length).toBeGreaterThan(10);
      expect(rep.violations).toEqual([]);
      expect(rep.nondeterministic).toEqual([]);
      expect(rep.evidenceMissing).toEqual([]);
    });
    it("use cases fire on attack logs and stay quiet on noise", () => {
      expect(source.useCases.length).toBeGreaterThanOrEqual(4);
      for (const [id, h] of Object.entries(rep.useCaseHits)) {
        if (!VOLUME.has(id)) expect(h.attack, `${id} never fires`).toBeGreaterThan(0);
        if ((h.severity === "high" || h.severity === "critical") && rep.noiseCount > 0) expect(h.noise / rep.noiseCount, id).toBeLessThan(0.02);
      }
    });
  });
}

describe("volume rules fire on a full wave", () => {
  const wave = (s: NativeSource, company: string) => Array.from({ length: 12 }, (_, i) => s.fromTelemetry({ id: `w${i}`, ts: new Date(Date.parse("2026-03-17T09:00:00Z") + i * 20_000).toISOString(), source: "web_server", vendor: "Web Server", event_type: "http_request",
    hostname: "web-app-01.example.com", src_ip: "203.0.113.60", dst_ip: "10.20.40.21", network: { url: "https://p.example.com/account/login", domain: "p.example.com", method: "POST", status: 401 }, raw: {} } as never, makeCtx(company))!);
  it("twelve failed sign-ins from one client in four minutes", () => {
    expect(runUseCase(iis.useCases.find(u => u.id === "iis.login_failures")!, wave(iis, "nexacorp")).length).toBeGreaterThan(0);
    expect(runUseCase(nginx.useCases.find(u => u.id === "nginx.login_failures")!, wave(nginx, "rocketstack")).length).toBeGreaterThan(0);
  });
});

describe("azure_waf anomaly scoring", () => {
  const ev = { id: "t1", ts: "2026-03-17T09:14:02.211Z", source: "waf", vendor: WEB_WAF_VENDOR, event_type: "waf_block", src_ip: "203.0.113.41",
    network: { url: "https://portal.example.com/download?file=..%2F...", domain: "portal.example.com", method: "GET" },
    raw: { "waf.action": "block", "waf.rule.key": "lfi_query", "waf.matched_data": "../", "waf.match_location": "ARGS:file" } } as never;
  it("a blocked request is a Matched rule row and a Blocked 949110 row on one transaction", () => {
    const ctx = makeCtx("nexacorp");
    const rule = azureWaf.fromTelemetry(ev, ctx)!;
    const [block] = azureWaf.companions!(ev, ctx);
    const p = (l: typeof rule) => l.record.properties as Record<string, unknown>;
    expect(p(rule).action).toBe("Matched");
    expect(p(block).action).toBe("Blocked");
    expect(p(block).ruleId).toBe("949110");
    expect(p(block).transactionId).toBe(p(rule).transactionId);
    expect(validateNative(block, azureWaf.schema)).toEqual([]);
  });
  it("a request no rule touched has no firewall row: it is an access log row", () => {
    const clean = { id: "t2", ts: "2026-03-17T09:15:00.000Z", source: "waf", vendor: WEB_WAF_VENDOR, event_type: "waf_allow", src_ip: "203.0.113.41", network: { url: "https://portal.example.com/x", domain: "portal.example.com", status: 200 }, raw: { "waf.action": "allow" } } as never;
    expect(azureWaf.fromTelemetry(clean, makeCtx("nexacorp"))?.kind).toBe("ApplicationGatewayAccessLog");
  });
});

describe("aws_waf decisions", () => {
  const rec = (raw: Record<string, unknown>, event_type = "waf_allow") => awsWaf.fromTelemetry({ id: "t3", ts: "2026-03-17T09:14:02.211Z", source: "waf", vendor: WEB_WAF_VENDOR, event_type, src_ip: "203.0.113.41",
    network: { url: "https://a.example.com/x", domain: "a.example.com" }, raw } as never, makeCtx("rocketstack"))!.record as Record<string, never>;
  it("a rule in Count passes with the default action and names the configured action", () => {
    const r = rec({ "waf.action": "count", "waf.rule.key": "xss_body" });
    expect(r.action).toBe("ALLOW");
    expect(r.terminatingRuleId).toBe("Default_Action");
    expect(JSON.stringify(r.ruleGroupList)).toContain('"overriddenAction":"BLOCK"');
  });
  it("a block terminates on the managed group, with the rule inside it", () => {
    const r = rec({ "waf.action": "block", "waf.rule.key": "sqli_query" }, "waf_block");
    expect(r.terminatingRuleId).toBe("AWS-AWSManagedRulesSQLiRuleSet");
    expect(r.terminatingRuleType).toBe("MANAGED_RULE_GROUP");
    expect(JSON.stringify(r.ruleGroupList)).toContain("SQLi_QUERYARGUMENTS");
  });
  it("the same client software keeps its TLS fingerprint across addresses", () => {
    const a = awsWaf.fromTelemetry({ id: "a", ts: "2026-03-17T09:14:02.211Z", source: "waf", vendor: WEB_WAF_VENDOR, event_type: "waf_allow", src_ip: "203.0.113.60", network: { url: "https://a.example.com/x", user_agent: "tool/1" }, raw: {} } as never, makeCtx("rocketstack"))!;
    const b = awsWaf.fromTelemetry({ id: "b", ts: "2026-03-17T09:14:03.211Z", source: "waf", vendor: WEB_WAF_VENDOR, event_type: "waf_allow", src_ip: "203.0.113.61", network: { url: "https://a.example.com/x", user_agent: "tool/1" }, raw: {} } as never, makeCtx("rocketstack"))!;
    expect(a.record.ja3Fingerprint).toBe(b.record.ja3Fingerprint);
  });
});

describe("web server wire formats", () => {
  const ev = { id: "t4", ts: "2026-03-17T09:21:40.000Z", source: "web_server", vendor: "Web Server", event_type: "http_request", hostname: "web-app-01.example.com", src_ip: "203.0.113.54", dst_ip: "10.20.40.21",
    network: { url: "https://portal.example.com/a?b=1", domain: "portal.example.com", method: "GET", status: 200, bytes_in: 43, bytes_out: 214, user_agent: "Mozilla/5.0 (X11; Linux)" }, raw: {} } as never;
  it("IIS: UTC, one token per field, + for a space, gateway in c-ip and the client in X-Forwarded-For", () => {
    const l = iis.fromTelemetry(ev, makeCtx("nexacorp"))!;
    expect(l.rawLine!.split(" ")).toHaveLength(FIELDS.length);
    expect(l.rawLine).toContain("Mozilla/5.0+(X11;+Linux)");
    expect(l.record.time).toBe("09:21:40");
    expect(l.record["c-ip"]).toBe("10.20.40.9");
    expect(l.record["X-Forwarded-For"]).toBe("203.0.113.54");
    expect(iisLine(l.record)).toBe(l.rawLine);
  });
  it("nginx: local time with its offset, the balancer first and the client in x_forwarded_for", () => {
    const l = nginx.fromTelemetry(ev, makeCtx("medcore"))!;
    expect(l.record.time_local).toBe("17/Mar/2026:10:21:40 +0100");
    expect(l.record.remote_addr).toBe("10.20.40.9");
    expect(l.record.http_x_forwarded_for).toBe("203.0.113.54");
    expect(l.rawLine).toContain('"GET /a?b=1 HTTP/1.1" 200 43');
  });
  it("timeLocal follows daylight saving", () => {
    expect(timeLocal("2026-07-01T12:00:00.000Z", "Europe/Berlin")).toBe("01/Jul/2026:14:00:00 +0200");
    expect(timeLocal("2026-01-01T12:00:00.000Z", "UTC")).toBe("01/Jan/2026:12:00:00 +0000");
  });
  it("a staff request comes through the balancer like any other, so the WAF and the server name one client", () => {
    const inside = { id: "t5", ts: "2026-03-17T09:21:40.000Z", source: "web_server", vendor: "Web Server", event_type: "http_request", hostname: "web-app-01.example.com", src_ip: "10.10.20.19", dst_ip: "10.20.40.21", network: { url: "https://portal.example.com/a", domain: "portal.example.com" }, raw: {} } as never;
    expect(nginx.fromTelemetry(inside, makeCtx("rocketstack"))!.record.http_x_forwarded_for).toBe("10.10.20.19");
    expect(iis.fromTelemetry(inside, makeCtx("nexacorp"))!.record["X-Forwarded-For"]).toBe("10.10.20.19");
  });
  it("a request the server made to itself never crossed the balancer", () => {
    const self = { id: "t6", ts: "2026-03-17T09:21:40.000Z", source: "web_server", vendor: "Microsoft IIS", event_type: "http_request", hostname: "web-app-01.example.com", src_ip: "::1", dst_ip: "10.20.40.21", dst_port: 80, network: { url: "https://portal.example.com/a", domain: "portal.example.com" }, raw: {} } as never;
    const r = iis.fromTelemetry(self, makeCtx("nexacorp"))!.record;
    expect(r["c-ip"]).toBe("::1");
    expect(r["s-port"]).toBe(80);
    expect(r["X-Forwarded-For"]).toBe("-");
  });
});
