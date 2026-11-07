// Every column a mapping names must exist in the real table: a typo would otherwise vanish silently.
import { describe, expect, it } from "vitest";
import { NATIVE_SOURCES } from "@/lib/logs/native";
import type { NativeLog, SourceId } from "@/lib/logs/native/types";
import { mapRow, specFor } from "./mapRow";
import { columnType, TABLE_NAMES } from "./tables";

const SOURCES = Object.keys(NATIVE_SOURCES) as SourceId[];
const ctx = { tenantId: "t", cloud: "azure_activity" as const };

const log = (sourceId: SourceId, kind: string, record: Record<string, unknown>): NativeLog => ({ sourceId, kind, format: "json", record, timeMs: Date.parse("2026-01-01T10:00:00Z") });

describe("mappings", () => {
  it("name only real columns of real tables", () => {
    const problems: string[] = [];
    let specs = 0;
    for (const id of SOURCES) for (const kind of Object.keys(NATIVE_SOURCES[id]!.schema.kinds)) {
      const spec = specFor(id, kind, "azure_activity");
      if (!spec) continue;
      specs++;
      if (!TABLE_NAMES.includes(spec.table)) problems.push(`${id}/${kind}: table ${spec.table}`);
      const fixed = typeof spec.fixed === "function" ? spec.fixed(ctx) : spec.fixed ?? {};
      for (const col of [...Object.keys(spec.cols), ...Object.keys(fixed)]) if (!columnType(spec.table, col)) problems.push(`${spec.table}.${col}`);
      if (spec.rest && !columnType(spec.table, spec.rest)) problems.push(`${spec.table}.${spec.rest}`);
    }
    expect([...new Set(problems)]).toEqual([]);
    expect(specs).toBeGreaterThan(60);
  });

  it("a source with no real table is left out, not forced into another", () => {
    for (const [id, kind] of [["servicenow", "incident"], ["workday", "activity"], ["zscaler_zpa", "user_activity"], ["cloudflare_access", "login"], ["sentinelone", "Process Creation"], ["sophos", "running_processes_windows_sophos"], ["m365", "DlpRuleMatch"]] as [SourceId, string][]) {
      expect(mapRow(log(id, kind, { a: 1 }), ctx), `${id}/${kind}`).toBeNull();
    }
    expect(mapRow(log("k8s_audit", "Event", {}), { tenantId: "t", cloud: "aws_cloudtrail" }), "EKS is not AKS").toBeNull();
  });

  it("Entra sign-in: flattened as the diagnostic export does", () => {
    const m = mapRow(log("entra", "signIn", {
      id: "1", ipAddress: "203.0.113.9", riskLevelDuringSignIn: "high", status: { errorCode: 50126, failureReason: "Invalid" }, location: { city: "Paris", countryOrRegion: "FR" },
    }), ctx)!;
    expect(m.table).toBe("SigninLogs");
    expect(m.row).toMatchObject({ IPAddress: "203.0.113.9", ResultType: "50126", ResultDescription: "Invalid", RiskLevelDuringSignIn: "high", Location: "FR", Category: "SignInLogs", AADTenantId: "t", Type: "SigninLogs" });
    expect(m.row.LocationDetails).toEqual({ city: "Paris", countryOrRegion: "FR" });
  });

  it("firewall: the CEF columns, the rest in AdditionalExtensions", () => {
    const m = mapRow(log("paloalto", "TRAFFIC", { type: "TRAFFIC", subtype: "end", src: "10.0.0.1", dst: "198.51.100.1", dport: "443", action: "allow", bytes_sent: "12", srcloc: "10.0.0.0-10.255.255.255" }), ctx)!;
    expect(m.table).toBe("CommonSecurityLog");
    expect(m.row).toMatchObject({ DeviceVendor: "Palo Alto Networks", DeviceProduct: "PAN-OS", SourceIP: "10.0.0.1", DestinationIP: "198.51.100.1", DestinationPort: 443, DeviceAction: "allow", SentBytes: 12, Activity: "TRAFFIC" });
    expect(String(m.row.AdditionalExtensions)).toContain("PanOSsrcloc=10.0.0.0-10.255.255.255");
  });

  it("Okta follows the connector's transform", () => {
    const m = mapRow(log("okta", "user.session.start", { eventType: "user.session.start", actor: { alternateId: "a@b.c", id: "00u1", type: "User" }, outcome: { result: "FAILURE", reason: "INVALID_CREDENTIALS" }, client: { ipAddress: "203.0.113.1" }, severity: "WARN", uuid: "u" }), ctx)!;
    expect(m.table).toBe("OktaV2_CL");
    expect(m.row).toMatchObject({ EventOriginalType: "user.session.start", ActorUsername: "a@b.c", ActorUsernameType: "UPN", ActorUserType: "Regular", SrcIpAddr: "203.0.113.1", EventResult: "Failure", OriginalOutcomeResult: "FAILURE", EventOriginalResultDetails: "INVALID_CREDENTIALS", EventSeverity: "Medium" });
  });

  it("a UAL record's kind is its RecordType, by name", () => {
    const m = mapRow(log("m365", "ExchangeAdmin", { Id: "i", Operation: "New-InboxRule", UserId: "a@b.c", ClientIP: "198.51.100.2:1234", Workload: "Exchange", UserType: 0 }), ctx)!;
    expect(m.table).toBe("OfficeActivity");
    expect(m.row).toMatchObject({ OfficeId: "i", Operation: "New-InboxRule", RecordType: "ExchangeAdmin", OfficeWorkload: "Exchange", UserType: "Regular" });
  });
});
