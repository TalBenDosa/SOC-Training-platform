import { describe, it, expect } from "vitest";
import { source, kindOf } from "./gcp_audit";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

function cardLogs(): NativeLog[] {
  const out: NativeLog[] = [];
  for (const s of cardSamples("cloud-gcp-audit.md")) {
    if (!s || typeof s !== "object") continue;
    const rec = s as Record<string, unknown>;
    const kind = kindOf(rec);
    if (!kind) continue;
    out.push({ sourceId: "gcp_audit", kind, format: "json", record: rec, timeMs: Date.parse(String(rec.timestamp ?? "2026-09-30T02:00:00Z")) });
  }
  return out;
}

describe("gcp_audit — card samples", () => {
  it("every LogEntry/AuditLog sample validates with zero violations", () => {
    const logs = cardLogs();
    expect(logs.length).toBeGreaterThanOrEqual(5);
    for (const log of logs) {
      const v = validateNative(log, source.schema);
      expect(v, `${JSON.stringify((log.record.protoPayload as any)?.methodName)} -> ${JSON.stringify(v)}`).toEqual([]);
    }
  });
});

describe("gcp_audit — corpus + cross-cloud render", () => {
  it("GCP-authored audit entries (RocketStack noise + the key-theft story) render as clean native LogEntries", () => {
    const native = corpusFor(source.schema.telemetrySources, source.schema.vendorMatch);
    let rendered = 0;
    for (const c of native) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      rendered++;
      expect(validateNative(log, source.schema), `${c.ev.id}`).toEqual([]);
      // the rendering company's project, never the authored one
      expect(JSON.stringify(log.record), `${c.ev.id} project`).not.toContain("rocketstack-data-prod");
      expect(String(log.record.logName)).toMatch(/cloudaudit\.googleapis\.com%2F(activity|data_access)$/);
    }
    console.log(`[gcp_audit] native cloud_gcp events: ${rendered}/${native.length} rendered`);
    expect(native.length).toBeGreaterThanOrEqual(14);
    expect(rendered / native.length).toBeGreaterThanOrEqual(0.95);
  });

  it("the minted key ties the service account's later reads back to the CreateServiceAccountKey", () => {
    const evs = corpusFor(source.schema.telemetrySources).filter(c => c.storyId === "gcp-sa-key-theft");
    const mint = evs.find(c => c.ev.id === "gcpkey_03_create_sa_key")!;
    const mintLog = source.fromTelemetry(mint.ev, makeCtx(mint.companyId))!;
    const keyName = String((mintLog.record.protoPayload as any).response.name);
    for (const id of ["gcpkey_05_list_objects", "gcpkey_06_get_objects", "gcpkey_07_access_secret"]) {
      const c = evs.find(x => x.ev.id === id)!;
      const pp = source.fromTelemetry(c.ev, makeCtx(c.companyId))!.record.protoPayload as any;
      expect(pp.authenticationInfo.serviceAccountKeyName, id).toBe(`//iam.googleapis.com/${keyName}`);
    }
  });

  it("Security Command Center findings are not audit-log entries: declined, never faked", () => {
    const scc = corpusFor(["cloud_gcp"]).filter(c => /security command center/i.test(c.ev.vendor ?? ""));
    expect(scc.length).toBeGreaterThanOrEqual(2);
    for (const c of scc) expect(source.fromTelemetry(c.ev, makeCtx(c.companyId)), c.ev.id).toBeNull();
  });

  it("renders AWS CloudTrail events as GCP equivalents where one exists; declines the rest", () => {
    const aws = corpusFor(["cloudtrail"]).filter(c => (c.ev.vendor ?? "").toLowerCase().includes("cloudtrail") && c.origin === "story");
    let rendered = 0;
    for (const c of aws) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      rendered++;
      const v = validateNative(log, source.schema);
      expect(v, `${c.ev.id} -> ${JSON.stringify(v)}`).toEqual([]);
    }
    console.log(`[gcp_audit] cross-cloud: ${rendered}/${aws.length} AWS story events have a true GCP equivalent and rendered clean`);
    expect(rendered).toBeGreaterThanOrEqual(10);
  });

  it("preserves evidence (IP, bucket, secret) on cross-cloud renders; deterministic", () => {
    for (const c of corpusFor(["cloudtrail"]).filter(c => c.origin === "story")) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      const blob = JSON.stringify(log.record);
      if (c.ev.src_ip) expect(blob, `${c.ev.id} ip`).toContain(c.ev.src_ip);
      // The bucket name is an object-path field only (storage.objects.*); a
      // project-level buckets.list legitimately does not name a bucket.
      const bucket = c.ev.raw["aws.cloudtrail.requestParameters.bucketName"] as string | undefined;
      if (bucket && String((log.record.protoPayload as any).methodName).includes("storage.objects")) {
        expect(blob, `${c.ev.id} bucket`).toContain(bucket);
      }
      expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(log);
    }
  });
});

describe("gcp_audit — use cases", () => {
  const storyGcp = corpusFor(["cloudtrail"])
    .filter(c => c.origin === "story")
    .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
    .filter((l): l is NativeLog => !!l);
  const attackLogs = [...cardLogs(), ...storyGcp];

  it("each use case fires on at least one card/cross-cloud log", () => {
    for (const uc of source.useCases) {
      const hits = runUseCase(uc, attackLogs);
      console.log(`[gcp_audit] ${uc.id}: ${hits.length} hit(s)`);
      expect(hits.length, `${uc.id} did not fire`).toBeGreaterThan(0);
    }
  });
});
