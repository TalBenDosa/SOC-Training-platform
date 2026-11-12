import { describe, it, expect } from "vitest";
import { source, kindOf, isGithubAudit, emuLogin } from "./github_audit";
import { corpus, cardSamples } from "../testing/corpus";
import { standardChecks } from "../testing/standardChecks";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { nativize } from "../index";
import type { TelemetryEvent } from "@/lib/sim/types";

/*
 * Card samples: every json block of vcs-github-audit.md is a streamed audit event (git.clone, repo.create,
 * pull_request.create, public_key.create, org.add_member); none is skipped.
 * GitHub Advanced Security alerts and webhook payloads (issues.opened, pull_request.merged) under a GitHub vendor
 * are other products: this module returns null for them and they keep their own view.
 */
type Rec = Record<string, unknown>;
const rows = corpus().filter(c => isGithubAudit(c.ev));

const clone = (id: string, repo: string, min: number): TelemetryEvent => ({
  id, ts: new Date(Date.parse("2026-11-12T09:00:00Z") + min * 60_000).toISOString(), source: "vcs", vendor: "GitHub Audit Log", event_type: "cloud_api_call", severity: "low",
  user_email: "a.novak@nexacorp.com", src_ip: "203.0.113.88",
  raw: { "github.action": "git.clone", "github.actor": "a-novak_nexacorp", "github.repo": repo, "github.visibility": "private", "github.programmatic_access_type": "Personal access token (classic)", "github.geo.country_code": "US" },
});

describe("github_audit: card samples", () => {
  it("validate with zero violations", () => {
    const samples = (cardSamples(source.schema.card) as Rec[]).filter(r => kindOf(r));
    expect(samples.length).toBe(5);
    for (const r of samples) expect(validateNative({ sourceId: "github_audit", kind: kindOf(r)!, format: "json", record: r, timeMs: 0 }, source.schema), String(r.action)).toEqual([]);
  });
});

describe("github_audit: standard checks", () => {
  const rep = standardChecks(source, kindOf, { cards: [source.schema.card] });
  it("records validate, evidence survives, output is deterministic", () => {
    expect(rows.length).toBeGreaterThan(5);
    expect(rep.violations.slice(0, 10)).toEqual([]);
    expect(rep.evidenceMissing.slice(0, 10)).toEqual([]);
    expect(rep.nondeterministic).toEqual([]);
  });
  it("use cases fire on stories or card samples and stay quiet on noise", () => {
    console.log(`[github_audit] corpus ${rows.length} audit events, use cases ${JSON.stringify(rep.useCaseHits)}`);
    for (const [id, h] of Object.entries(rep.useCaseHits)) if (h.severity === "high" || h.severity === "critical") expect(h.noise, id).toBeLessThanOrEqual(Math.max(1, rep.noiseCount * 0.02));
  });
});

describe("github_audit: rendering", () => {
  it("one token keeps one hash across calls, and a git event names the repository and transport", () => {
    const ctx = makeCtx("nexacorp");
    const a = source.fromTelemetry(clone("g1", "nexacorp-eng/payments-api", 0), ctx)!;
    const b = source.fromTelemetry(clone("g2", "nexacorp-eng/billing-ui", 1), ctx)!;
    expect(a.kind).toBe("git");
    expect(a.record.hashed_token).toBe(b.record.hashed_token);
    expect(a.record.token_id).toBe(b.record.token_id);
    expect(a.record).toMatchObject({ repository: "nexacorp-eng/payments-api", repository_public: false, transport_protocol: 1, transport_protocol_name: "http", operation_type: "access", actor_location: { country_code: "US" }, org: "nexacorp-eng" });
    expect(typeof a.record["@timestamp"]).toBe("number");
    expect(a.record.external_identity_nameid).toBe("a.novak@nexacorp.com");
  });
  it("is the record every stack shows, and a webhook payload is not rendered as an audit event", () => {
    expect(nativize(clone("g3", "x/y", 0), "nexacorp")?.sourceId).toBe("github_audit");
    expect(nativize(clone("g3", "x/y", 0), "rocketstack", { cloud: "aws_cloudtrail" })?.sourceId).toBe("github_audit");
    const webhook = { ...clone("g4", "x/y", 0), source: "cloudtrail", raw: { "github.action": "issues.opened", "github.actor": "d.shapira" } } as TelemetryEvent;
    expect(nativize(webhook, "rocketstack")).toBeNull();
  });
  it("the bulk-clone rule counts distinct repositories", () => {
    const ctx = makeCtx("nexacorp");
    const same = Array.from({ length: 12 }, (_, i) => source.fromTelemetry(clone(`s${i}`, "nexacorp-eng/payments-api", i * 0.5), ctx)!);
    const many = Array.from({ length: 12 }, (_, i) => source.fromTelemetry(clone(`m${i}`, `nexacorp-eng/repo-${i}`, i * 0.5), ctx)!);
    const uc = source.useCases.find(u => u.id === "github_audit.bulk-clone")!;
    expect(runUseCase(uc, same)).toHaveLength(0);
    expect(runUseCase(uc, many).length).toBeGreaterThan(0);
  });
  it("an EMU login is derived from the corporate address", () => {
    expect(emuLogin("m.ben-david@rocketstack.io", "rocketstack")).toBe("m-ben-david_rocketstack");
  });
});
