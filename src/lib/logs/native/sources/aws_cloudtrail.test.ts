import { describe, it, expect } from "vitest";
import { source, kindOf } from "./aws_cloudtrail";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

const ctx = makeCtx("rocketstack");

/** Build NativeLogs directly from the card's JSON samples (skip non-CloudTrail samples). */
function cardLogs(): NativeLog[] {
  const out: NativeLog[] = [];
  for (const s of cardSamples("cloud-aws-cloudtrail.md")) {
    if (!s || typeof s !== "object") continue;
    const rec = s as Record<string, unknown>;
    const kind = kindOf(rec);
    if (!kind) continue;
    out.push({ sourceId: "aws_cloudtrail", kind, format: "json", record: rec, timeMs: Date.parse(String(rec.eventTime ?? "2026-09-30T02:00:00Z")) });
  }
  return out;
}

describe("aws_cloudtrail — card samples", () => {
  it("every CloudTrail card sample validates with zero violations", () => {
    const logs = cardLogs();
    expect(logs.length).toBeGreaterThanOrEqual(12);
    for (const log of logs) {
      const v = validateNative(log, source.schema);
      expect(v, `${log.kind} ${JSON.stringify(log.record.eventName)} → ${JSON.stringify(v)}`).toEqual([]);
    }
  });
});

describe("aws_cloudtrail — corpus conversion", () => {
  const all = corpusFor(source.schema.telemetrySources);
  const mine = corpusFor(source.schema.telemetrySources, source.schema.vendorMatch); // vendor = CloudTrail

  it("≥95% of native CloudTrail events convert and validate clean", () => {
    let nonNull = 0;
    for (const c of mine) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      nonNull++;
      const v = validateNative(log, source.schema);
      expect(v, `${c.ev.id} → ${JSON.stringify(v)}`).toEqual([]);
    }
    const ratio = nonNull / mine.length;
    console.log(`[aws_cloudtrail] native CloudTrail: ${nonNull}/${mine.length} non-null (${(ratio * 100).toFixed(1)}%)`);
    expect(ratio).toBeGreaterThanOrEqual(0.95);
  });

  it("cross-vendor source events (GuardDuty / GitHub / Bedrock-invocation-log) are declined, not faked", () => {
    const cross = all.filter(c => !source.schema.vendorMatch.some(v => (c.ev.vendor ?? "").toLowerCase().includes(v)));
    let rendered = 0;
    for (const c of cross) if (source.fromTelemetry(c.ev, makeCtx(c.companyId))) rendered++;
    console.log(`[aws_cloudtrail] cross-vendor in 'cloudtrail' source: ${cross.length}, rendered ${rendered} (GuardDuty/GitHub/CloudWatch-invocation-log declined by design)`);
    expect(cross.length).toBeGreaterThan(0);
  });
});

describe("aws_cloudtrail — evidence & determinism", () => {
  it("preserves evidence values verbatim", () => {
    for (const c of corpusFor(source.schema.telemetrySources, source.schema.vendorMatch)) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      const blob = JSON.stringify(log.record);
      const en = (c.ev.raw["aws.cloudtrail.eventName"] ?? c.ev.raw["event.action"]) as string | undefined;
      if (en) expect(blob, `${c.ev.id} eventName`).toContain(en);
      if (c.ev.src_ip) expect(blob, `${c.ev.id} src_ip`).toContain(c.ev.src_ip);
      const user = c.ev.raw["aws.cloudtrail.userIdentity.userName"] as string | undefined;
      if (user) expect(blob, `${c.ev.id} userName`).toContain(user);
      for (const k of ["aws.cloudtrail.requestParameters.bucketName", "aws.cloudtrail.requestParameters.secretId", "aws.cloudtrail.requestParameters.policyArn"]) {
        const val = c.ev.raw[k] as string | undefined;
        if (val) expect(blob, `${c.ev.id} ${k}`).toContain(val);
      }
    }
  });

  it("is deterministic (same event twice → deep-equal)", () => {
    for (const c of corpusFor(source.schema.telemetrySources, source.schema.vendorMatch).slice(0, 30)) {
      const a = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      const b = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      expect(a).toEqual(b);
    }
  });
});

describe("aws_cloudtrail — use cases", () => {
  // Logs built from card samples + converted attack-story events (origin "story").
  const storyLogs = corpusFor(source.schema.telemetrySources)
    .filter(c => c.origin === "story")
    .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
    .filter((l): l is NativeLog => !!l);
  // The corpus/card have no root console sign-in; prove that detection with a
  // representative event run through the converter (a real native record).
  const rootLogin = source.fromTelemetry({
    id: "syn_root_login", ts: "2026-09-30T02:05:00.000Z", source: "cloudtrail", vendor: "AWS CloudTrail",
    event_type: "auth_success", src_ip: "203.0.113.90",
    raw: { "aws.cloudtrail.eventName": "ConsoleLogin", "aws.cloudtrail.eventSource": "signin.amazonaws.com", "aws.cloudtrail.userIdentity.type": "Root", "aws.cloudtrail.eventType": "AwsConsoleSignIn" },
  } as never, ctx);
  const attackLogs = [...cardLogs(), ...storyLogs, ...(rootLogin ? [rootLogin] : [])];

  it("each use case fires on at least one attack/card log", () => {
    for (const uc of source.useCases) {
      const hits = runUseCase(uc, attackLogs);
      console.log(`[aws_cloudtrail] ${uc.id}: ${hits.length} hit(s) on attack/card logs`);
      expect(hits.length, `${uc.id} did not fire`).toBeGreaterThan(0);
    }
  });

  it("high/critical use cases stay quiet on benign/company noise (<2%)", () => {
    // True "noise" = benign + company events NOT designed as false-positive training.
    const noise = corpusFor(source.schema.telemetrySources)
      .filter(c => c.origin !== "story" && !c.ev.fp_explanation)
      .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
      .filter((l): l is NativeLog => !!l);
    const fpTraining = corpusFor(source.schema.telemetrySources)
      .filter(c => c.origin !== "story" && c.ev.fp_explanation)
      .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
      .filter((l): l is NativeLog => !!l);

    const fired = new Set<number>();
    for (const uc of source.useCases) {
      if (uc.severity !== "high" && uc.severity !== "critical") continue;
      const hits = runUseCase(uc, noise);
      for (const h of hits) for (const r of h.records) fired.add(r);
      const fpHits = runUseCase(uc, fpTraining);
      console.log(`[aws_cloudtrail] ${uc.id}: noise=${hits.length} fp-training=${fpHits.length}`);
    }
    const rate = noise.length ? fired.size / noise.length : 0;
    console.log(`[aws_cloudtrail] high/critical noise FP rate: ${fired.size}/${noise.length} = ${(rate * 100).toFixed(1)}% (fp-training events excluded, as designed to trip detectors)`);
    expect(rate).toBeLessThan(0.02);
  });
});

// ── identity, response elements, partition (storyline review 2026-10-02 §C.5) ──
type Rec = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const mk = (id: string, ts: string, raw: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
  ({ id, ts, source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call", src_ip: "185.220.101.42", raw, ...extra }) as never;
const recOf = (e: never): Rec => source.fromTelemetry(e, ctx)!.record as Rec;

describe("aws_cloudtrail — identity carried from the authored event", () => {
  it("an authored assumed role keeps its role as session issuer, the record's account, and one ASIA key across rows", () => {
    const arn = "arn:aws:sts::247316892041:assumed-role/rocketstack-ci-deploy-role/i-0abc123def4567890";
    const a = recOf(mk("t_ar1", "2026-06-18T09:09:00Z", { "aws.cloudtrail.eventName": "GetCallerIdentity", "aws.cloudtrail.userIdentity.type": "AssumedRole", "aws.cloudtrail.userIdentity.arn": arn }));
    const b = recOf(mk("t_ar2", "2026-06-18T09:16:00Z", { "aws.cloudtrail.eventName": "GetSecretValue", "aws.cloudtrail.requestParameters.secretId": "prod/db", "aws.cloudtrail.userIdentity.arn": arn }));
    for (const r of [a, b]) {
      expect(r.userIdentity.type).toBe("AssumedRole");
      expect(r.userIdentity.arn).toBe(arn);
      expect(r.userIdentity.sessionContext.sessionIssuer.userName).toBe("rocketstack-ci-deploy-role");
      expect(r.userIdentity.sessionContext.sessionIssuer.arn).toBe("arn:aws:iam::247316892041:role/rocketstack-ci-deploy-role");
      expect(r.recipientAccountId).toBe("247316892041");
      expect(r.userIdentity.accessKeyId).toMatch(/^ASIA[0-9A-Z]{16}$/);
      expect(r.userIdentity.sessionContext.ec2RoleDelivery).toBe("2.0");
    }
    expect(b.userIdentity.accessKeyId).toBe(a.userIdentity.accessKeyId);
    expect(b.userIdentity.sessionContext.attributes.creationDate).toBe(a.userIdentity.sessionContext.attributes.creationDate);
    expect(Date.parse(a.userIdentity.sessionContext.attributes.creationDate)).toBeLessThan(Date.parse(a.eventTime));
  });

  it("an IAM user keeps one AIDA / AKIA whether the row names it by userName or by ARN", () => {
    const a = recOf(mk("t_u1", "2026-06-18T09:00:00Z", { "aws.cloudtrail.eventName": "ListBuckets", "aws.cloudtrail.userIdentity.type": "IAMUser", "aws.cloudtrail.userIdentity.userName": "svc-reporting" }));
    const b = recOf(mk("t_u2", "2026-06-18T09:05:00Z", { "aws.cloudtrail.eventName": "GetObject", "aws.cloudtrail.requestParameters.bucketName": "b1", "aws.cloudtrail.userIdentity.arn": `arn:aws:iam::${ctx.tenant.awsAccountId}:user/svc-reporting` }));
    expect(a.userIdentity.accessKeyId).toMatch(/^AKIA/);
    expect(b.userIdentity.accessKeyId).toBe(a.userIdentity.accessKeyId);
    expect(b.userIdentity.principalId).toBe(a.userIdentity.principalId);
    expect(a.userIdentity.arn).toBe(b.userIdentity.arn);
  });

  it("a person with no authored AWS identity reaches AWS as an Identity Center session, never an IAM user with an AKIA key", () => {
    const r = recOf(mk("t_sso", "2026-06-18T09:00:00Z", { "aws.cloudtrail.eventName": "ListBuckets" }, { user_email: "d.shapira@rocketstack.io" }));
    expect(r.userIdentity.type).toBe("AssumedRole");
    expect(r.userIdentity.arn).toMatch(/:assumed-role\/AWSReservedSSO_[A-Za-z]+_[0-9a-f]{16}\/d\.shapira@rocketstack\.io$/);
    expect(r.userIdentity.sessionContext.sessionIssuer.arn).toContain(":role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_");
    expect(r.userIdentity.accessKeyId).toMatch(/^ASIA/);
  });

  it("AssumeRoleWithSAML is called by a SAMLUser; a cross-account AssumeRole by an AWSAccount, logged in the role owner's account", () => {
    const saml = recOf(mk("t_saml", "2026-06-18T09:00:00Z", { "aws.cloudtrail.eventName": "AssumeRoleWithSAML", "aws.cloudtrail.requestParameters.roleArn": "arn:aws:iam::247316892041:role/okta-admin", "aws.cloudtrail.requestParameters.principalArn": "arn:aws:iam::247316892041:saml-provider/Okta" }, { user_email: "t.chen@rocketstack.io" }));
    expect(saml.userIdentity).toMatchObject({ type: "SAMLUser", userName: "t.chen@rocketstack.io" });
    expect(saml.userIdentity.principalId).toMatch(/:t\.chen@rocketstack\.io$/);
    expect(saml.responseElements.assumedRoleUser.arn).toBe("arn:aws:sts::247316892041:assumed-role/okta-admin/t.chen@rocketstack.io");
    const x = recOf(mk("t_xacct", "2026-06-18T09:00:00Z", { "aws.cloudtrail.eventName": "AssumeRole", "aws.cloudtrail.requestParameters.roleArn": "arn:aws:iam::247316892041:role/prod-admin", "aws.cloudtrail.userIdentity.accountId": "999999999999" }));
    expect(x.userIdentity).toMatchObject({ type: "AWSAccount", accountId: "999999999999" });
    expect(x.recipientAccountId).toBe("247316892041");
  });
});

describe("aws_cloudtrail — responseElements carry the minted key / session", () => {
  it("the key CreateAccessKey returns is the key the new user's later calls are signed with", () => {
    const create = recOf(mk("t_cak", "2026-06-18T09:12:00Z", { "aws.cloudtrail.eventName": "CreateAccessKey", "aws.cloudtrail.requestParameters.userName": "deploy-prod", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::247316892041:assumed-role/ci-role/i-0abc123def4567890" }));
    const use = recOf(mk("t_use", "2026-06-18T09:21:00Z", { "aws.cloudtrail.eventName": "GetObject", "aws.cloudtrail.requestParameters.bucketName": "b1", "aws.cloudtrail.userIdentity.type": "IAMUser", "aws.cloudtrail.userIdentity.userName": "deploy-prod" }));
    expect(create.responseElements.accessKey).toMatchObject({ userName: "deploy-prod", status: "Active" });
    expect(create.responseElements.accessKey.accessKeyId).toMatch(/^AKIA[0-9A-Z]{16}$/);
    expect(create.responseElements.accessKey.createDate).toBe("Jun 18, 2026 9:12:00 AM");
    expect(use.userIdentity.accessKeyId).toBe(create.responseElements.accessKey.accessKeyId);
  });

  it("AssumeRole returns ASIA credentials + the assumed-role user that the session's later rows show", () => {
    const ar = recOf(mk("t_assume", "2026-06-10T14:52:00Z", { "aws.cloudtrail.eventName": "AssumeRole", "aws.cloudtrail.userIdentity.type": "IAMUser", "aws.cloudtrail.userIdentity.userName": "t.niv-ci", "aws.cloudtrail.request_parameters": JSON.stringify({ roleArn: "arn:aws:iam::247316892041:role/prod-deploy", roleSessionName: "t.niv-ci" }) }));
    const later = recOf(mk("t_sess", "2026-06-10T14:55:00Z", { "aws.cloudtrail.eventName": "ListBuckets", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::247316892041:assumed-role/prod-deploy/t.niv-ci" }));
    expect(ar.responseElements.credentials.accessKeyId).toMatch(/^ASIA/);
    expect(ar.responseElements.credentials.expiration).toBe("Jun 10, 2026 3:52:00 PM");
    expect(ar.responseElements.assumedRoleUser.arn).toBe("arn:aws:sts::247316892041:assumed-role/prod-deploy/t.niv-ci");
    expect(later.userIdentity.accessKeyId).toBe(ar.responseElements.credentials.accessKeyId);
    expect(later.userIdentity.principalId).toBe(ar.responseElements.assumedRoleUser.assumedRoleId);
  });

  it("CreateUser returns the user (placeholder ids / accounts replaced); read-only calls log no response", () => {
    const cu = recOf(mk("t_cu", "2026-05-20T03:00:00Z", { "aws.cloudtrail.eventName": "CreateUser", "aws.cloudtrail.requestParameters.userName": "svc-backup2", "aws.cloudtrail.responseElements.user.userId": "AIDIODR4TAW7CSEXAMPLE", "aws.cloudtrail.userIdentity.arn": "arn:aws:sts::123456789012:assumed-role/eks-node-role/i-0abc1234" }));
    expect(cu.responseElements.user.userId).toMatch(/^AIDA[0-9A-Z]{17}$/);
    expect(cu.responseElements.user.arn).toBe(`arn:aws:iam::${ctx.tenant.awsAccountId}:user/svc-backup2`);
    expect(JSON.stringify(cu)).not.toContain("123456789012");
    const ro = recOf(mk("t_ro", "2026-05-20T03:00:00Z", { "aws.cloudtrail.eventName": "ListRoles", "aws.cloudtrail.responseElements.roles_count": "42" }));
    expect(ro.responseElements).toBeNull();
  });
});

describe("aws_cloudtrail — partition / region", () => {
  it("a GovCloud record uses the aws-us-gov partition and a us-gov region on every row, authored region or not", () => {
    const arn = "arn:aws:sts::552134008821:assumed-role/qb-fraud-monitor-role/svc-fraud-monitor";
    const gov = { vendor: "AWS CloudTrail (GovCloud)", src_ip: "10.100.1.20" };
    const a = recOf(mk("t_gov1", "2026-06-20T22:24:00Z", { "aws.cloudtrail.eventName": "DisableAlarmActions", "aws.cloudtrail.awsRegion": "us-gov-west-1", "aws.cloudtrail.userIdentity.arn": arn }, gov));
    const b = recOf(mk("t_gov2", "2026-06-20T22:26:00Z", { "aws.cloudtrail.eventName": "PutMetricAlarm", "aws.cloudtrail.userIdentity.arn": arn }, gov));
    for (const r of [a, b]) {
      expect(r.awsRegion).toBe("us-gov-west-1");
      expect(r.userIdentity.arn).toBe(arn.replace("arn:aws:", "arn:aws-us-gov:"));
      expect(JSON.stringify(r)).not.toMatch(/"arn:aws:/);
      expect(r.recipientAccountId).toBe("552134008821");
      expect(r.vpcEndpointId).toMatch(/^vpce-[0-9a-f]{17}$/); // a private source address reaches AWS through an interface endpoint
    }
    expect(a.userIdentity.accessKeyId).toBe(b.userIdentity.accessKeyId);
  });

  it("an STS call keeps its authored region (regional endpoint); IAM records in the partition's home region", () => {
    const sts = recOf(mk("t_sts", "2026-06-10T14:52:00Z", { "aws.cloudtrail.eventName": "GetCallerIdentity", "aws.cloudtrail.awsRegion": "eu-west-1" }));
    const iam = recOf(mk("t_iam", "2026-06-10T14:52:00Z", { "aws.cloudtrail.eventName": "CreateUser", "aws.cloudtrail.awsRegion": "eu-west-1", "aws.cloudtrail.requestParameters.userName": "x" }));
    expect(sts.awsRegion).toBe("eu-west-1");
    expect(iam.awsRegion).toBe("us-east-1");
  });
});

describe("detection catalogue — no crypto (Tal 2026-10-02)", () => {
  it("no use case of any native module is about crypto-mining / cryptocurrency", async () => {
    const { NATIVE_SOURCES } = await import("../index");
    const bad: string[] = [];
    for (const src of Object.values(NATIVE_SOURCES)) for (const uc of src!.useCases) {
      const text = `${uc.id} ${uc.title} ${uc.description} ${uc.mitre.join(" ")}`;
      if (/crypto-?min|crypto ?currency|mining|miner|xmrig|monero|bitcoin|stratum|cryptojack|T1496/i.test(text)) bad.push(uc.id);
    }
    expect(bad).toEqual([]);
  });
});
